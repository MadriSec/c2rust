#include <cmath>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <llvm-14/llvm/ADT/Optional.h>
#include <ostream>
#include <unordered_map>
#include <utility>

#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclBase.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/Type.h"
// Declares clang::SyntaxOnlyAction.

#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"

#include "clang/AST/RecordLayout.h"
#include "clang/Basic/Version.h"
#include "clang/Frontend/CompilerInstance.h"
#if CLANG_VERSION_MAJOR < 10
#include "clang/Frontend/LangStandard.h"
#else
#endif // CLANG_VERSION_MAJOR < 10

#include "AstAnalyzer.hpp"
#include <tinycbor/cbor.h>

using namespace llvm;
using namespace clang;
using namespace clang::ast_matchers;

void HeapInfo::encode(CborEncoder *encoder) {
    CborEncoder local;
    cbor_encoder_create_array(encoder, &local, CborIndefiniteLength);
    cbor_encode_uint(&local, nb_elements);
    if (nb_elements > 1) {
        cbor_encode_boolean(&local, is_constant);
    }
    cbor_encoder_close_container(encoder, &local);
}

void AnalysisResult::encode(CborEncoder *encoder) {
    CborEncoder local;
    cbor_encoder_create_array(encoder, &local, CborIndefiniteLength);
    if (heap_info.hasValue()) {
        heap_info.getValue().encode(&local);
    } else {
        cbor_encode_null(&local);
    }
    cbor_encoder_close_container(encoder, &local);
}

DeclarationMatcher MallocMatcher =
    varDecl(
        hasInitializer(ignoringImpCasts( // Initialized variable declaration
            callExpr(
                callee(functionDecl(
                    hasName("malloc"))), // That is a call to malloc
                hasArgument(
                    0,     // With its first argument being
                    anyOf( // either
                        sizeOfExpr(unaryExprOrTypeTraitExpr(hasArgumentOfType(
                            qualType().bind("declaredType")))), // sizeof(t)
                        binaryOperator( // or n * sizeof(t)
                            hasOperatorName("*"),
                            hasEitherOperand(ignoringParenImpCasts(sizeOfExpr(
                                unaryExprOrTypeTraitExpr(
                                    hasArgumentOfType(
                                        qualType().bind("declaredType")))
                                    .bind("avoid")))))
                            .bind("binaryOperator")))))))
        .bind("mallocInitVA");

DeclarationMatcher CallocMatcher =
    varDecl(hasInitializer(ignoringImpCasts( // Initialized variable declaration
                callExpr(                    // that is a call
                    callee(functionDecl(hasName("calloc"))), // to calloc
                    hasArgument(0, expr().bind("nbElements")),
                    hasArgument(
                        1, // With its second argument being
                        sizeOfExpr(unaryExprOrTypeTraitExpr(hasArgumentOfType(
                            qualType().bind("declaredType")))) // sizeof(t)
                        ))
                    .bind("init"))))
        .bind("callocInitVA");

class HeapAllocationAnalyzer : public MatchFinder::MatchCallback {
    // This stores analysis information gathered from matchers, but also
    // ultimately from static analysis
    std::unordered_map<void *, AnalysisResult> *analysis_results;

    ASTContext *Context;
    bool coherent_types(const MatchFinder::MatchResult &result,
                        const VarDecl *var_decl) {
        const Type *vd_type = var_decl->getType().getTypePtr();
        if (!vd_type->isPointerType()) {
            return false;
        }
        QualType pointee_type = vd_type->getPointeeType();
        const QualType *declared_type =
            result.Nodes.getNodeAs<clang::QualType>("declaredType");
        if (declared_type->isNull()) {
            std::cerr << "Could not get declared type";
            return false;
        }
        return pointee_type == *declared_type;
    };
    bool handle_malloc(const VarDecl *var_decl,
                       const MatchFinder::MatchResult result,
                       size_t *nb_elements, bool *is_constant) {
        if (!coherent_types(result, var_decl)) {
            return false;
        }
        const BinaryOperator *elem_count =
            result.Nodes.getNodeAs<clang::BinaryOperator>("binaryOperator");

        if (elem_count == NULL) {
            return false;
        }

        Expr *nb_elem_expr = elem_count->getLHS()->IgnoreImpCasts();
        if (nb_elem_expr == result.Nodes.getNodeAs<clang::Expr>("avoid")) {
            nb_elem_expr = elem_count->getRHS()->IgnoreImpCasts();
        }
        *is_constant =
            nb_elem_expr->isConstantInitializer(*Context, false, NULL);
        *nb_elements = (size_t)nb_elem_expr;

        return true;
    }

    bool handle_calloc(const VarDecl *var_decl,
                       const MatchFinder::MatchResult result,
                       size_t *nb_elements, bool *is_constant) {
        if (!coherent_types(result, var_decl)) {
            return false;
        }
        *nb_elements = 0;
        const Expr *nb_elem_expr = result.Nodes.getNodeAs<Expr>("nbElements");
        *is_constant =
            nb_elem_expr->isConstantInitializer(*Context, false, NULL);
        if (is_constant) {
            Expr::EvalResult result;
            nb_elem_expr->EvaluateAsInt(result, *Context);
            *nb_elements = result.Val.getInt().getExtValue();
        }
        if (*nb_elements != 1) {
            *nb_elements = (size_t)nb_elem_expr;
        }
        return true;
    }

  public:
    explicit HeapAllocationAnalyzer(
        std::unordered_map<void *, AnalysisResult> *results,
        ASTContext *context)
        : analysis_results(results), Context(context) {};

    virtual void run(const MatchFinder::MatchResult &result) {
        size_t nb_elements = 1;
        bool is_constant = false;

        bool success = false;

        const VarDecl *var_decl;
        if ((var_decl =
                 result.Nodes.getNodeAs<clang::VarDecl>("mallocInitVA"))) {
            success =
                handle_malloc(var_decl, result, &nb_elements, &is_constant);
        } else if ((var_decl = result.Nodes.getNodeAs<clang::VarDecl>(
                        "callocInitVA"))) {
            success =
                handle_calloc(var_decl, result, &nb_elements, &is_constant);
        }

        if (!success) {
            return;
        }
        AnalysisResult analysis_result =
            AnalysisResult(HeapInfo(nb_elements, is_constant));
        if (!analysis_results->emplace((void *)var_decl, analysis_result)
                 .second) {
            std::cerr << "Variable was not successfully inserted :/\n";
        };
        const CallExpr *init = result.Nodes.getNodeAs<CallExpr>("init");
        if (init == NULL) {
            return;
        }
        if (!analysis_results->emplace((void *)init, analysis_result).second) {
            std::cerr << "Variable was not successfully inserted ._.\n";
        }
    }
};

DeclarationMatcher ReturnFinder =
    functionDecl(hasBody(compoundStmt(
                     hasDescendant(returnStmt().bind("returnStatement")))))
        .bind("functionDeclaration");

class FunctionAnalyzer : public MatchFinder::MatchCallback {
    std::unordered_map<void *, AnalysisResult> *analysis_results;

    ASTContext *Context;

  public:
    explicit FunctionAnalyzer(
        std::unordered_map<void *, AnalysisResult> *results,
        ASTContext *context)
        : analysis_results(results), Context(context) {};

    virtual void run(const MatchFinder::MatchResult &result) {
        if (const FunctionDecl *function_decl =
                result.Nodes.getNodeAs<clang::FunctionDecl>(
                    "functionDeclaration")) {
            function_decl->dump();
            const ReturnStmt *return_stmt =
                result.Nodes.getNodeAs<ReturnStmt>("returnStatement");
            if (return_stmt == NULL) {
                return;
            }
            return_stmt->dump();
        }
    }
};

void analyse_context(
    std::unordered_map<void *, AnalysisResult> *analysis_results,
    ASTContext *Context) {
    HeapAllocationAnalyzer heap_allocation_analyzer =
        HeapAllocationAnalyzer(analysis_results, Context);
    FunctionAnalyzer function_analyzer =
        FunctionAnalyzer(analysis_results, Context);
    MatchFinder Finder;
    Finder.addMatcher(MallocMatcher, &heap_allocation_analyzer);
    Finder.addMatcher(CallocMatcher, &heap_allocation_analyzer);
    Finder.addMatcher(ReturnFinder, &function_analyzer);
    Finder.matchAST(*Context);
}