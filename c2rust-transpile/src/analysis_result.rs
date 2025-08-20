use c2rust_ast_builder::mk;
use c2rust_ast_exporter::clang_ast::{from_value, Value};
use proc_macro2::{Group, Punct, Span, TokenTree};
use syn::{Expr, Type, __private::ToTokens, token};

use crate::{
    c_ast::{CExprId, CTypeId, IdMapper},
    diagnostics::TranslationResult,
    translator::{ExprContext, Translation},
    with_stmts::WithStmts,
    StdUse,
};

#[derive(Debug, Clone, Copy)]
pub enum LengthInfo {
    One,
    Expr { expr_id: CExprId, is_constant: bool },
}

#[derive(Debug, Clone, Copy)]
pub struct PointerInfo {
    is_alloc: bool,
    is_heap: bool,
    declared_type: CTypeId,
    length_info: LengthInfo,
}

impl PointerInfo {
    pub fn generate_type(
        &self,
        translation: &Translation,
        ctx: ExprContext,
    ) -> TranslationResult<Box<Type>> {
        if !self.is_heap {
            todo!()
        }
        let pointee_ty = translation.convert_type(self.declared_type)?;
        match self.length_info {
            LengthInfo::One => Ok(make_boxed_ty(pointee_ty)),
            LengthInfo::Expr {
                expr_id,
                is_constant,
            } => type_with_length_expr(translation, ctx, &expr_id, pointee_ty, is_constant),
        }
    }

    pub fn generate_alloc(
        &self,
        translation: &Translation,
        ctx: ExprContext,
    ) -> TranslationResult<WithStmts<Box<Expr>>> {
        if !self.is_heap {
            todo!()
        }
        let default = translation
            .implicit_default_expr(self.declared_type, true)?
            .into_value();
        match self.length_info {
            LengthInfo::One => make_single_initializer(default),
            LengthInfo::Expr {
                expr_id,
                is_constant,
            } => alloc_with_length_expr(translation, ctx, &expr_id, default, is_constant),
        }
    }

    pub fn is_alloc(&self) -> bool {
        self.is_alloc
    }
}

impl From<(Vec<Value>, &mut IdMapper)> for PointerInfo {
    fn from(imported: (Vec<Value>, &mut IdMapper)) -> Self {
        let is_alloc = from_value::<bool>(imported.0[0].clone())
            .expect("PointerInfo should tell if call is an allocation");
        let is_heap = from_value::<bool>(imported.0[1].clone())
            .expect("PointerInfo should tell if pointer points to heap");

        let ty_old = from_value::<u64>(imported.0[2].clone())
            .expect("PointerInfo should contain declared type");

        let nb_elements = from_value::<u64>(imported.0[3].clone())
            .expect("PointerInfo whould contain length info in first element");

        let ty = imported.1.get_or_create_new(ty_old);
        let length_info = if nb_elements == 1 {
            LengthInfo::One
        } else {
            let new_id = imported.1.get_or_create_new(nb_elements);
            let is_constant = from_value::<bool>(imported.0[4].clone())
                .expect("Expression variants should contain constantness value");
            LengthInfo::Expr {
                expr_id: CExprId(new_id),
                is_constant,
            }
        };
        PointerInfo {
            declared_type: CTypeId(ty),
            length_info,
            is_alloc,
            is_heap,
        }
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
fn type_with_length_expr(
    translation: &Translation,
    ctx: ExprContext,
    c_length_id: &CExprId,
    pointee_ty: Box<Type>,
    is_constant: bool,
) -> TranslationResult<Box<Type>> {
    Ok(if is_constant {
        let length = translation.convert_expr(ctx, *c_length_id)?.into_value();
        make_boxed_array_ty(pointee_ty, length)
    } else {
        make_boxed_slice_ty(pointee_ty)
    })
}

#[inline]
fn alloc_with_dynamic_length_expr(
    translation: &Translation,
    length: TranslationResult<WithStmts<Box<Expr>>>,
    length_type: &str,
    default: Box<Expr>,
) -> TranslationResult<WithStmts<Box<Expr>>> {
    let length = match length {
        Ok(l) => l.into_value(),
        Err(e) => return Err(e),
    };
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
    Ok(WithStmts::new_val(mk().method_call_expr(
        mk().mac_expr(mk().mac(
            mk().path(vec!["vec"]),
            vec![default_tokens, semicolon, length_tokens],
            syn::MacroDelimiter::Bracket(token::Bracket(Span::call_site())),
        )),
        "into_boxed_slice",
        vec![],
    )))
}
#[inline]
fn alloc_with_length_expr(
    translation: &Translation,
    ctx: ExprContext,
    c_length_id: &CExprId,
    default: Box<Expr>,
    is_constant: bool,
) -> TranslationResult<WithStmts<Box<Expr>>> {
    let length = translation.convert_expr(ctx, *c_length_id);

    if is_constant {
        let l = length?.into_value();

        Ok(WithStmts::new_val(mk().call_expr(
            mk().path_expr(vec!["Box", "new"]),
            vec![mk().repeat_expr(default, l)],
        )))
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
        alloc_with_dynamic_length_expr(translation, length, length_type.as_str(), default)
    }
}
