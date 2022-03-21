using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace autoruns.virustotal.VirusTotal
{
    public class YearMonthDayConverter : JsonConverter<DateTime>
    {
        private readonly CultureInfo _culture = new CultureInfo("en-us");
        private const string _newDateTimeFormat = "yyyyMMdd";
        private const string _oldDateTimeFormat = "yyyyMMddHHmmss";

        public override DateTime Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            DateTime result;

            if (reader.ValueSpan.IsEmpty)
                return DateTime.MinValue;

            string stringVal = reader.GetString();

            //New format
            if (DateTime.TryParseExact(stringVal, _newDateTimeFormat, _culture, DateTimeStyles.AllowWhiteSpaces, out result))
                return result;

            //Old format
            if (DateTime.TryParseExact(stringVal, _oldDateTimeFormat, _culture, DateTimeStyles.AllowWhiteSpaces, out result))
                return result;

            throw new InvalidOperationException("Invalid date/time from VirusTotal. Tried to parse: " + stringVal);
        }

        public override void Write(Utf8JsonWriter writer, DateTime value, JsonSerializerOptions options)
        {
            writer.WriteStringValue(value.ToString(_newDateTimeFormat));
        }
    }
}
