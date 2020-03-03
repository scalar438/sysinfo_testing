fn main()
{
    for s in std::env::args()
    {
        println!("{}", s);
    }
    std::thread::sleep(std::time::Duration::from_millis(2000));
}