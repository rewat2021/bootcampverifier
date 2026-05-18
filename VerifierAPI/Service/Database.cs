namespace VerifierAPI.Service
{
    public static class Database
    {
        private static readonly string DataPath = Path.Combine(Environment.CurrentDirectory, "Data");
        public static void Write(string table, string key, string value, IWebHostEnvironment env)
        {
            var path = Path.Combine(env.ContentRootPath, key + ".txt");

            using (var sw = new StreamWriter(path))
            {
                sw.Write(value);
            }
        }
        public static string Read(string table, string key, IWebHostEnvironment env)
        {
            var path = Path.Combine(env.ContentRootPath, key + ".txt");
            try
            {
                string lines = File.ReadAllText(path);
                return lines;
            }
            catch (Exception ex)
            {
                return "";
            }
        }

        public static string ReadDID(string table, string key, IWebHostEnvironment env)
        {
            var path = Path.Combine(env.ContentRootPath, key + ".txt");
            try
            {
                string lines = File.ReadAllText(path);
                return lines;
            }
            catch (Exception ex)
            {
                return "";
            }
        }


    }
}
