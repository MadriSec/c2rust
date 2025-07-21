use c2rust_ast_builder::mk;
use proc_macro2::{Group, Punct, Span, TokenTree};
use syn::{Expr, Type, __private::ToTokens, token};

use crate::{
    c_ast::CExprId,
    diagnostics::TranslationResult,
    translator::{ExprContext, Translation},
    with_stmts::WithStmts,
    StdUse,
};

#[derive(Debug, Clone, Copy)]
pub enum HeapInfo {
    None,
    One,
    Expr { expr_id: CExprId, is_constant: bool },
}

impl HeapInfo {
    pub fn is_some(&self) -> bool {
        !matches!(self, HeapInfo::None)
    }

    pub fn generate_declaration(
        &self,
        translation: &Translation,
        ctx: ExprContext,
        default: Box<Expr>,
        pointee_ty: Box<Type>,
    ) -> TranslationResult<(Box<Type>, TranslationResult<WithStmts<Box<Expr>>>)> {
        Ok(match self {
            HeapInfo::None => return Err("Heap conversion occured without heap information".into()),
            HeapInfo::One => (make_boxed_ty(pointee_ty), make_single_initializer(default)),
            HeapInfo::Expr {
                expr_id,
                is_constant,
            } => handle_length_expr(translation, ctx, expr_id, default, pointee_ty, *is_constant)?,
        })
    }
}

#[inline]
fn make_boxed_ty(pointee_ty: Box<Type>) -> Box<Type> {
    mk().path_ty(vec![mk().path_segment_with_args(
        "Box",
        mk().angle_bracketed_args(vec![pointee_ty]),
    )])
}
#[inline]
fn make_single_initializer(default: Box<Expr>) -> TranslationResult<WithStmts<Box<Expr>>> {
    Ok(WithStmts::new_val(mk().call_expr(
        mk().path_expr(vec!["Box", "new"]),
        vec![default],
    )))
}
#[inline]
fn make_boxed_array_ty(pointee_ty: Box<Type>, length: Box<Expr>) -> Box<Type> {
    mk().path_ty(vec![mk().path_segment_with_args(
        "Box",
        mk().angle_bracketed_args(vec![mk().array_ty(pointee_ty, length)]),
    )])
}
#[inline]
fn make_boxed_slice_ty(pointee_ty: Box<Type>) -> Box<Type> {
    mk().path_ty(vec![mk().path_segment_with_args(
        "Box",
        mk().angle_bracketed_args(vec![mk().slice_ty(pointee_ty)]),
    )])
}

#[inline]
fn handle_dynamic_length_expr(
    translation: &Translation,
    length: Box<Expr>,
    length_type: &str,
    default: Box<Expr>,
    pointee_ty: Box<Type>,
) -> (Box<Type>, TranslationResult<WithStmts<Box<Expr>>>) {
    let casted_length = match length_type {
        "u16" | "u8" => mk().call_expr(mk().path_expr(vec!["usize", "from"]), vec![length]),
        _ => {
            translation.std_use(StdUse::TryFrom);
            mk().method_call_expr(
                mk().call_expr(mk().path_expr(vec!["usize", "try_from"]), vec![length]),
                "unwrap",
                Vec::new(),
            )
        }
    };
    let default_tokens = TokenTree::Group(Group::new(
        proc_macro2::Delimiter::None,
        ToTokens::to_token_stream(&default),
    ));
    let semicolon = TokenTree::Punct(Punct::new(';', proc_macro2::Spacing::Alone));
    let length_tokens = TokenTree::Group(Group::new(
        proc_macro2::Delimiter::None,
        ToTokens::to_token_stream(&casted_length),
    ));
    (
        make_boxed_slice_ty(pointee_ty),
        Ok(WithStmts::new_val(mk().method_call_expr(
            mk().mac_expr(mk().mac(
                mk().path(vec!["vec"]),
                vec![default_tokens, semicolon, length_tokens],
                syn::MacroDelimiter::Bracket(token::Bracket(Span::call_site())),
            )),
            "into_boxed_slice",
            vec![],
        ))),
    )
}
#[inline]
fn handle_length_expr(
    translation: &Translation,
    ctx: ExprContext,
    c_length_id: &CExprId,
    default: Box<Expr>,
    pointee_ty: Box<Type>,
    is_constant: bool,
) -> TranslationResult<(Box<Type>, TranslationResult<WithStmts<Box<Expr>>>)> {
    let length = translation.convert_expr(ctx, *c_length_id)?.into_value();

    Ok(if is_constant {
        (
            make_boxed_array_ty(pointee_ty, length.clone()),
            Ok(WithStmts::new_val(mk().call_expr(
                mk().path_expr(vec!["Box", "new"]),
                vec![mk().repeat_expr(default, length)],
            ))),
        )
    } else {
        let length_type = match *translation.convert_type(
            translation.ast_context[*c_length_id]
                .kind
                .get_type()
                .unwrap(),
        )? {
            Type::Path(t) => t.path.segments[0].ident.to_string(),
            _ => unreachable!(), // Is it really unreachable ?
        };
        handle_dynamic_length_expr(
            translation,
            length,
            length_type.as_str(),
            default,
            pointee_ty,
        )
    })
}
