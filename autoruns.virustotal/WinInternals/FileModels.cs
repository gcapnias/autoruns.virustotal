using CsvHelper.Configuration;
using System;
using System.Collections.Generic;
using System.Text;

namespace autoruns.virustotal.WinInternals
{
    public class FileEntry
    {
        public string Time { get; set; }
        public string EntryLocation { get; set; }
        public string Entry { get; set; }
        public string Enabled { get; set; }
        public string Category { get; set; }
        public string Profile { get; set; }
        public string Description { get; set; }
        public string Company { get; set; }
        public string ImagePath { get; set; }
        public string Version { get; set; }
        public string LaunchString { get; set; }
    }

    public class FileEntryMapper : ClassMap<FileEntry>
    {
        public FileEntryMapper()
        {
            Map(m => m.Time).Name("Time");
            Map(m => m.EntryLocation).Name("Entry Location");
            Map(m => m.Entry).Name("Entry");
            Map(m => m.Enabled).Name("Enabled");
            Map(m => m.Category).Name("Category");
            Map(m => m.Profile).Name("Profile");
            Map(m => m.Description).Name("Description");
            Map(m => m.Company).Name("Company");
            Map(m => m.ImagePath).Name("Image Path");
            Map(m => m.Version).Name("Version");
            Map(m => m.LaunchString).Name("Launch String");
        }
    }

}
