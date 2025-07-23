#include "tinycbor/cbor.h"
#include "clang/AST/ASTContext.h"
#include <unordered_map>

using namespace clang;

class HeapInfo {
    size_t nb_elements;
    bool is_constant;

  public:
    HeapInfo(size_t nb_elements, bool constantness)
        : nb_elements(nb_elements), is_constant(constantness) {};
    void encode(CborEncoder *encoder);
};

class AnalysisResult {
    Optional<HeapInfo> heap_info;

  public:
    AnalysisResult() : heap_info({}) {};
    AnalysisResult(HeapInfo hi) : heap_info(hi) {};
    void encode(CborEncoder *encoder);
};

void analyse_context(
    std::unordered_map<void *, AnalysisResult> *analysis_results,
    ASTContext *Context);