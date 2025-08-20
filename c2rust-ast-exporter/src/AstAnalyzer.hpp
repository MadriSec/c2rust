#include "tinycbor/cbor.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Type.h"
#include <cstdint>
#include <unordered_map>

using namespace clang;

class PointerInfo {
    bool is_alloc;
    bool is_heap;
    const Type *declared_type;
    size_t nb_elements;
    bool is_constant;

  public:
    PointerInfo(bool is_alloc, bool is_heap, const Type *type,
                size_t nb_elements, bool constantness)
        : is_alloc(is_alloc), is_heap(is_heap), nb_elements(nb_elements),
          is_constant(constantness), declared_type(type) {};
    void encode(CborEncoder *encoder);

    const Type *get_type();

    void unset_is_alloc();
    bool get_is_alloc() { return is_alloc; }
};

class AnalysisResult {
    Optional<PointerInfo> pointer_info;

  public:
    AnalysisResult() : pointer_info({}) {};
    AnalysisResult(PointerInfo pi) : pointer_info(pi) {};
    void encode(CborEncoder *encoder);
    Optional<PointerInfo> get_pointer_info();
    void unset_ptr_is_alloc();
};

class AnalysisResults {
    std::unordered_map<uintptr_t, AnalysisResult> map;

  public:
    bool changed;
    AnalysisResults() : map(), changed(false) {};
    void reset_changed() { changed = false; }
    bool add_result(uintptr_t node, AnalysisResult analysis_result);
    Optional<AnalysisResult> get_analysis_result(uintptr_t ast_node);
    void erase(uintptr_t node);
};

void analyse_context(AnalysisResults *analysis_results, ASTContext *Context);