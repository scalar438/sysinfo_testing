fn main()
{
    for s in std::env::args()
    {
        println!("{}", s);
    }
    std::thread::sleep_ms(2000);
}