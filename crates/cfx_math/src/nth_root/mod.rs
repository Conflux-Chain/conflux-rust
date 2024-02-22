mod compute;
mod const_generic;
mod inv;
mod root_degree;
#[cfg(test)]
mod tests;

pub use self::{
    compute::NthRoot, const_generic::RootInvParams, inv::nth_inv_root,
    root_degree::RootDegree,
};

pub fn nth_root<N: RootDegree, I: NthRoot>(input: I) -> I {
    input.nth_root::<N>()
}
