using autoruns.virustotal.VirusTotal;
using autoruns.virustotal.WinInternals;
using CsvHelper;
using RestSharp;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;

namespace autoruns.virustotal
{
    class Program
    {
        static IEnumerable<FileRequest> fileRequests = null;

        static void Main(string[] args)
        {
            FileInfo listfile = null;
            string apikey = null;

            if (args.Length > 1)
            {
                listfile = new FileInfo(args[1].Trim());
            }

            if (args.Length > 0)
            {
                apikey = args[0].Trim();
            }

            if (args.Length == 0 || string.IsNullOrEmpty(apikey) || (!Console.IsInputRedirected && (listfile == null || !listfile.Exists)))
            {
                Console.Out.WriteLine("Usage:");
                Console.Out.WriteLine($"autoruns.virustotal {{apikey}} [filelist]");
                Console.Out.WriteLine();
                Console.Out.WriteLine("apikey   - Your Virus Total API key");
                Console.Out.WriteLine("filelist - File containing the list of files to check, created with autorunsc.exe with option -c");
                return;
            }


            string tempFolder = Environment.GetEnvironmentVariable("TEMP");
            Console.Out.WriteLine($"System's %TEMP% folder  : {tempFolder}");
            string windoewsFolfer = $"{Environment.GetEnvironmentVariable("windir")}";
            Console.Out.WriteLine($"System's %WINDIR% folder: {windoewsFolfer}");


            if (Console.IsInputRedirected)
            {
                Console.Out.WriteLine("Input from console redirection...");

                using (var csv = new CsvReader(Console.In, CultureInfo.InvariantCulture))
                {
                    csv.Context.RegisterClassMap<FileEntryMapper>();
                    IEnumerable<FileEntry> fileEntries = csv.GetRecords<FileEntry>();

                    fileRequests = fileEntries.Where(f => !string.IsNullOrEmpty(f.ImagePath))
                        .Where(f => f.ImagePath.StartsWith(tempFolder, StringComparison.InvariantCultureIgnoreCase) || f.ImagePath.StartsWith(windoewsFolfer, StringComparison.InvariantCultureIgnoreCase))
                        .GroupBy(f => f.ImagePath)
                        .Select(g => g.FirstOrDefault())
                        .OrderBy(f => f.ImagePath)
                        .Select(f => new FileRequest() { Company = f.Company, Description = f.Description, ImagePath = f.ImagePath, Version = f.Version })
                        .ToArray();

                }
            }
            else
            {
                Console.Out.WriteLine($"Input from file: {listfile.Name}");

                using (var reader = new StreamReader(listfile.FullName))
                using (var csv = new CsvReader(reader, CultureInfo.InvariantCulture))
                {
                    csv.Context.RegisterClassMap<FileEntryMapper>();
                    IEnumerable<FileEntry> fileEntries = csv.GetRecords<FileEntry>();

                    fileRequests = fileEntries.Where(f => !string.IsNullOrEmpty(f.ImagePath))
                        .Where(f => f.ImagePath.StartsWith(tempFolder, StringComparison.InvariantCultureIgnoreCase) || f.ImagePath.StartsWith(windoewsFolfer, StringComparison.InvariantCultureIgnoreCase))
                        .GroupBy(f => f.ImagePath)
                        .Select(g => g.FirstOrDefault())
                        .OrderBy(f => f.ImagePath)
                        .Select(f => new FileRequest() { Company = f.Company, Description = f.Description, ImagePath = f.ImagePath, Version = f.Version })
                        .ToArray();

                }
            }

            if (fileRequests != null && fileRequests.Count() > 0)
            {
                using (MD5 md5 = MD5.Create())
                {
                    Console.Out.WriteLine();
                    Console.Out.WriteLine("Files to check:");
                    foreach (FileRequest fileRequest in fileRequests)
                    {
                        using (var stream = File.OpenRead(fileRequest.ImagePath))
                        {
                            string hash = BitConverter.ToString(md5.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
                            fileRequest.MD5Hash = hash;

                            Console.Out.WriteLine($"[{hash}] {fileRequest.ImagePath}");
                        }
                    }
                }

                string resources = string.Join(",", fileRequests.Select(m => m.MD5Hash).ToArray());

                RestClient client = new RestClient("https://www.virustotal.com/vtapi/v2");
                RestRequest request = new RestRequest("/file/report", Method.Get)
                    .AddQueryParameter("apikey", apikey)
                    .AddQueryParameter("resource", resources)
                    .AddQueryParameter("allinfo", "false");

                RestResponse response = client.ExecuteGetAsync(request).Result;

                if (response.IsSuccessful)
                {
                    Console.Out.WriteLine();
                    string payload = response.Content;

                    if (!string.IsNullOrEmpty(payload))
                    {
                        File.WriteAllText("autoruns.virustotal,json", payload);

                        if (payload.StartsWith("["))
                        {
                            FileReport[] fileReports = JsonSerializer.Deserialize<FileReport[]>(payload);
                            Console.Out.WriteLine($"Results returned: {fileReports.Length}");

                            foreach (FileReport fileReport in fileReports)
                            {
                                GenerateReport(fileReport);
                            }
                        }
                        else
                        {
                            Console.Out.WriteLine("Result:");

                            FileReport fileReport = JsonSerializer.Deserialize<FileReport>(payload);
                            GenerateReport(fileReport);
                        }
                    }
                }
                else
                {
                    Console.Out.WriteLine("The request to Total Virus API was not successful!");
                }

            }
            else
            {
                Console.Out.WriteLine("There are no files to request information for!");
            }

        }

        private static void GenerateReport(FileReport fileReport)
        {
            FileRequest fileRequest = fileRequests.Where(f => f.MD5Hash.Equals(fileReport.MD5)).FirstOrDefault();
            if (fileRequest != null)
            {
                Console.Out.WriteLine($"[{fileReport.MD5}] {fileRequest.ImagePath}");
                Console.Out.WriteLine($"- Engines scanned this resource: {fileReport.Total} - Positives: {fileReport.Positives}");

                if (fileReport.Positives > 0)
                {
                    string names = string.Join(",", fileReport.Scans.Values.Where(s => s.Detected).Select(s => s.Result).ToArray());
                    Console.Out.WriteLine($"- Results: {names}");
                }
            }
        }
    }

    public class FileRequest
    {
        public string Description { get; set; }
        public string Company { get; set; }
        public string ImagePath { get; set; }
        public string Version { get; set; }
        public string MD5Hash { get; set; }
    }



}
