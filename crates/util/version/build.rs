use vergen_git2::{Emitter, Git2Builder, RustcBuilder};
fn main() -> anyhow::Result<()> {
    let git2 = Git2Builder::default().all().sha(true).build()?;
    Emitter::default()
        .add_instructions(&git2)?
        .add_instructions(&RustcBuilder::all_rustc()?)?
        .emit()
}
