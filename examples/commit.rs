use osv;

#[async_std::main]
async fn main() {
    let commit = "6879efc2c1596d11a6a6ad296f80063b558d5e0f";
    let res = osv::query_commit(commit).await.unwrap();
    println!("{:#?}", res);
}
