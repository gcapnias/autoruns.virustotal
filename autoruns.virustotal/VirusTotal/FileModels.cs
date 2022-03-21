using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json.Serialization;

namespace autoruns.virustotal.VirusTotal
{
    public class FileReport
    {
        /// <summary>
        /// MD5 hash of the resource.
        /// </summary>
        [JsonPropertyName("md5")]
        public string MD5 { get; set; }

        /// <summary>
        /// A permanent link that points to this specific scan.
        /// </summary>
        [JsonPropertyName("permalink")]
        public string Permalink { get; set; }

        /// <summary>
        /// How many engines flagged this resource.
        /// </summary>
        [JsonPropertyName("positives")]
        public int Positives { get; set; }

        /// <summary>
        /// Contains the id of the resource. Can be a SHA256, MD5 or other hash type.
        /// </summary>
        [JsonPropertyName("resource")]
        public string Resource { get; set; }

        /// <summary>
        /// The date the resource was last scanned.
        /// </summary>
        [JsonPropertyName("scan_date")]
        public string ScanDate { get; set; }

        /// <summary>
        /// Contains the scan id for this result.
        /// </summary>
        [JsonPropertyName("scan_id")]
        public string ScanId { get; set; }

        /// <summary>
        /// The scan results from each engine.
        /// </summary>
        [JsonPropertyName("scans")]
        public Dictionary<string, ScanEngine> Scans { get; set; }

        /// <summary>
        /// SHA1 hash of the resource.
        /// </summary>
        [JsonPropertyName("sha1")]
        public string SHA1 { get; set; }

        /// <summary>
        /// SHA256 hash of the resource.
        /// </summary>
        [JsonPropertyName("sha256")]
        public string SHA256 { get; set; }

        /// <summary>
        /// How many engines scanned this resource.
        /// </summary>
        [JsonPropertyName("total")]
        public int Total { get; set; }

        /// <summary>
        /// The response code. Use this to determine the status of the report.
        /// </summary>
        [JsonPropertyName("response_code")]
        public FileReportResponseCode ResponseCode { get; set; }

        /// <summary>
        /// Contains the message that corresponds to the response code.
        /// </summary>
        [JsonPropertyName("verbose_msg")]
        public string VerboseMsg { get; set; }
    }

    public class ScanEngine
    {
        /// <summary>
        /// True if the engine flagged the resource.
        /// </summary>
        [JsonPropertyName("detected")]
        public bool Detected { get; set; }

        /// <summary>
        /// Version of the engine.
        /// </summary>
        [JsonPropertyName("version")]
        public string Version { get; set; }

        /// <summary>
        /// Contains the name of the malware, if any.
        /// </summary>
        [JsonPropertyName("result")]
        public string Result { get; set; }

        /// <summary>
        /// The date of the latest signatures of the engine.
        /// </summary>
        [JsonConverter(typeof(YearMonthDayConverter))]
        [JsonPropertyName("update")]
        public DateTime Update { get; set; }
    }

}
