#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <llvm-14/llvm/ADT/Optional.h>
#include <ostream>
#include <sys/types.h>
#include <unordered_map>

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

void PointerInfo::encode(CborEncoder *encoder) {
    CborEncoder local;
    cbor_encoder_create_array(encoder, &local, CborIndefiniteLength);
    cbor_encode_boolean(&local, is_alloc);
    cbor_encode_boolean(&local, is_heap);
    cbor_encode_uint(&local, (uintptr_t)declared_type);
    cbor_encode_uint(&local, nb_elements);
    if (nb_elements > 1) {
        cbor_encode_boolean(&local, is_constant);
    }
    cbor_encoder_close_container(encoder, &local);
}
const Type *PointerInfo::get_type() { return this->declared_type; }
void PointerInfo::unset_is_alloc() { this->is_alloc = false; }

void AnalysisResult::encode(CborEncoder *encoder) {
    CborEncoder local;
    cbor_encoder_create_array(encoder, &local, CborIndefiniteLength);
    if (pointer_info.hasValue()) {
        pointer_info.getValue().encode(&local);
    } else {
        cbor_encode_null(&local);
    }
    cbor_encoder_close_container(encoder, &local);
}
Optional<PointerInfo> AnalysisResult::get_pointer_info() {
    return this->pointer_info;
}
void AnalysisResult::unset_ptr_is_alloc() {

    if (pointer_info.hasValue()) {

        PointerInfo pi = pointer_info.getValue();
        pi.unset_is_alloc();
        this->pointer_info = pi;
        pi.get_is_alloc();
    }
}

bool AnalysisResults::add_result(uintptr_t node,
                                 AnalysisResult analysis_result) {

    analysis_result.get_pointer_info().hasValue();
    // this should change when implementing analysis result merging
    changed |= map.emplace(node, analysis_result).second;
    return changed;
}
Optional<AnalysisResult>
AnalysisResults::get_analysis_result(uintptr_t ast_node) {
    auto res = map.find(ast_node);
    if (res != map.end()) {
        return res->second;
    } else {
        return {};
    }
}
void AnalysisResults::erase(uintptr_t node) { map.erase(node); }

auto MallocExpr =
    callExpr(
        callee(functionDecl(hasName("malloc"))), // That is a call to malloc
        hasArgument(
            0,     // With its first argument being
            anyOf( // either
                sizeOfExpr(unaryExprOrTypeTraitExpr(hasArgumentOfType(
                    qualType().bind("declaredType")))), // sizeof(t)
                binaryOperator(                         // or n * sizeof(t)
                    hasOperatorName("*"),
                    hasEitherOperand(ignoringParenImpCasts(sizeOfExpr(
                        unaryExprOrTypeTraitExpr(
                            hasArgumentOfType(qualType().bind("declaredType")))
                            .bind("avoid")))))
                    .bind("binaryOperator"))))
        .bind("mallocCall");
auto CallocExpr =
    callExpr(                                    // that is a call
        callee(functionDecl(hasName("calloc"))), // to calloc
        hasArgument(0, expr().bind("nbElements")),
        hasArgument(1, // With its second argument being
                    sizeOfExpr(unaryExprOrTypeTraitExpr(hasArgumentOfType(
                        qualType().bind("declaredType")))) // sizeof(t)
                    ))
        .bind("callocCall");

class HeapAllocationAnalyzer : public MatchFinder::MatchCallback {
    // This stores analysis information gathered from matchers, but also
    // ultimately from static analysis
    AnalysisResults *analysis_results;

    ASTContext *Context;

    bool handle_malloc(const MatchFinder::MatchResult result,
                       size_t *nb_elements, bool *is_constant) {
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
    bool handle_calloc(const MatchFinder::MatchResult result,
                       size_t *nb_elements, bool *is_constant) {
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
    explicit HeapAllocationAnalyzer(AnalysisResults *results,
                                    ASTContext *context)
        : analysis_results(results), Context(context) {};

    virtual void run(const MatchFinder::MatchResult &result) {
        size_t nb_elements = 1;
        bool is_constant = false;

        bool success = false;

        const CallExpr *heap_allocation;
        if ((heap_allocation =
                 result.Nodes.getNodeAs<CallExpr>("callocCall"))) {
            success = handle_calloc(result, &nb_elements, &is_constant);
        } else if ((heap_allocation =
                        result.Nodes.getNodeAs<CallExpr>("mallocCall"))) {
            success = handle_malloc(result, &nb_elements, &is_constant);
        }

        const QualType *declared_type =
            result.Nodes.getNodeAs<clang::QualType>("declaredType");

        if (!success) {
            return;
        }

        AnalysisResult analysis_result = AnalysisResult(PointerInfo(
            true, true, declared_type->split().Ty, nb_elements, is_constant));

        if (!analysis_results->add_result((uintptr_t)heap_allocation,
                                          analysis_result)) {
            std::cerr << "Heap allocation call analysis was not successfully "
                         "inserted ._.\n";
        }
    }
};

DeclarationMatcher HeapVarDeclFinder =
    varDecl(hasInitializer(ignoringImpCasts(expr().bind("initializer"))))
        .bind("variableDeclaration");
class HeapVarDeclPropagator : public MatchFinder::MatchCallback {
    AnalysisResults *analysis_results;

    ASTContext *Context;

  public:
    explicit HeapVarDeclPropagator(AnalysisResults *results,
                                   ASTContext *context)
        : analysis_results(results), Context(context) {};

    virtual void run(const MatchFinder::MatchResult &result) {
        const VarDecl *var_declaration =
            result.Nodes.getNodeAs<VarDecl>("variableDeclaration");
        if (var_declaration == NULL) {
            return;
        }
        const Expr *initializer = result.Nodes.getNodeAs<Expr>("initializer");
        if (initializer == NULL) {
            return;
        }
        Optional<AnalysisResult> maybe_analysis_result =
            analysis_results->get_analysis_result((uintptr_t)initializer);
        if (!maybe_analysis_result.hasValue()) {
            return;
        }
        AnalysisResult analysis_result = maybe_analysis_result.getValue();
        Optional<PointerInfo> maybe_pointer_info =
            analysis_result.get_pointer_info();
        if (!maybe_pointer_info.hasValue()) {
            return;
        }
        PointerInfo pointer_info = maybe_pointer_info.getValue();
        const Type *declared_type = pointer_info.get_type();

        if (pointer_info.get_is_alloc() &&
            declared_type !=
                var_declaration->getType()->getPointeeType().split().Ty) {
            analysis_results->erase((uintptr_t)initializer->IgnoreImpCasts());
            std::cerr << "Type missmatch detected for "
                      << var_declaration->getNameAsString() << std::endl;
            return;
        }

        analysis_result.unset_ptr_is_alloc();
        analysis_result.get_pointer_info()->get_is_alloc();
        analysis_results->add_result((uintptr_t)var_declaration,
                                     analysis_result);
    }
};

DeclarationMatcher ReturnFinder =
    functionDecl(hasBody(compoundStmt(hasDescendant(
                     returnStmt(hasReturnValue(ignoringImpCasts(
                                    expr().bind("returnExpression"))))
                         .bind("returnStatement")))))
        .bind("functionDeclaration");
class FunctionAnalyzer : public MatchFinder::MatchCallback {
    AnalysisResults *analysis_results;

    ASTContext *Context;

    Optional<AnalysisResult> handle_declref(const DeclRefExpr *decl_ref) {
        const ValueDecl *origin = (decl_ref->getDecl());
        Optional<AnalysisResult> maybe_analysis_result =
            analysis_results->get_analysis_result((uintptr_t)origin);
        if (!maybe_analysis_result.hasValue()) {
            return {};
        }
        AnalysisResult analysis_result = maybe_analysis_result.getValue();
        analysis_results->add_result((uintptr_t)decl_ref, analysis_result);
        return analysis_result;
    }

  public:
    explicit FunctionAnalyzer(AnalysisResults *results, ASTContext *context)
        : analysis_results(results), Context(context) {};

    virtual void run(const MatchFinder::MatchResult &result) {
        const FunctionDecl *function_decl =
            result.Nodes.getNodeAs<clang::FunctionDecl>("functionDeclaration");

        if (function_decl == NULL) {
            return;
        }

        const ReturnStmt *return_stmt =
            result.Nodes.getNodeAs<ReturnStmt>("returnStatement");
        if (return_stmt == NULL) {
            return;
        }
        const Expr *return_expr =
            result.Nodes.getNodeAs<Expr>("returnExpression");
        if (return_expr == NULL) {
            return;
        }

        const DeclRefExpr *decl_ref =
            result.Nodes.getNodeAs<DeclRefExpr>("returnExpression");
        Optional<AnalysisResult> maybe_analysis_result = {};
        if (decl_ref != NULL) {
            maybe_analysis_result = handle_declref(decl_ref);
        } else {
            maybe_analysis_result =
                analysis_results->get_analysis_result((uintptr_t)return_expr);
        }

        if (!maybe_analysis_result.hasValue()) {
            return;
        }
        AnalysisResult analysis_result = maybe_analysis_result.getValue();
        analysis_result.unset_ptr_is_alloc();
        analysis_results->add_result((uintptr_t)function_decl, analysis_result);
    }
};

auto CallExprMatcher =
    callExpr(callee(functionDecl(isDefinition()).bind("calleeDef")))
        .bind("callExpr");
class CallExprPropagator : public MatchFinder::MatchCallback {
    AnalysisResults *analysis_results;

    ASTContext *Context;

  public:
    explicit CallExprPropagator(AnalysisResults *results, ASTContext *context)
        : analysis_results(results), Context(context) {};

    virtual void run(const MatchFinder::MatchResult &result) {
        const CallExpr *call_expr =
            result.Nodes.getNodeAs<CallExpr>("callExpr");
        if (call_expr == NULL) {
            return;
        }
        const FunctionDecl *function_decl =
            result.Nodes.getNodeAs<FunctionDecl>("calleeDef");
        if (function_decl == NULL) {
            return;
        }

        Optional<AnalysisResult> maybe_analysis_result =
            analysis_results->get_analysis_result((uintptr_t)function_decl);
        if (!maybe_analysis_result.hasValue()) {
            return;
        }
        AnalysisResult analysis_result = maybe_analysis_result.getValue();

        analysis_results->add_result((uintptr_t)call_expr, analysis_result);
    }
};

void match_heap_allocations(AnalysisResults *analysis_results,
                            ASTContext *Context) {
    HeapAllocationAnalyzer heap_allocation_analyzer =
        HeapAllocationAnalyzer(analysis_results, Context);
    MatchFinder heap_alloc_finder;
    heap_alloc_finder.addMatcher(MallocExpr, &heap_allocation_analyzer);
    heap_alloc_finder.addMatcher(CallocExpr, &heap_allocation_analyzer);
    heap_alloc_finder.matchAST(*Context);
}
void match_variable_declarations(AnalysisResults *analysis_results,
                                 ASTContext *Context) {
    HeapVarDeclPropagator heap_var_decl_propagator =
        HeapVarDeclPropagator(analysis_results, Context);
    MatchFinder decl_finder = MatchFinder();
    decl_finder.addMatcher(HeapVarDeclFinder, &heap_var_decl_propagator);
    decl_finder.matchAST(*Context);
}
void match_fuction_returns(AnalysisResults *analysis_results,
                           ASTContext *Context) {
    FunctionAnalyzer function_analyzer =
        FunctionAnalyzer(analysis_results, Context);
    MatchFinder result_finder = MatchFinder();
    result_finder.addMatcher(ReturnFinder, &function_analyzer);
    result_finder.matchAST(*Context);
}
void match_call_expressions(AnalysisResults *analysis_results,
                            ASTContext *Context) {
    CallExprPropagator call_expr_propagator =
        CallExprPropagator(analysis_results, Context);
    MatchFinder call_expr_finder = MatchFinder();
    call_expr_finder.addMatcher(CallExprMatcher, &call_expr_propagator);
    call_expr_finder.matchAST(*Context);
}

void analyse_context(AnalysisResults *analysis_results, ASTContext *context) {
    match_heap_allocations(analysis_results, context);
    do {
        analysis_results->reset_changed();
        match_variable_declarations(analysis_results, context);
        match_fuction_returns(analysis_results, context);
        match_call_expressions(analysis_results, context);
    } while (analysis_results->changed);
}