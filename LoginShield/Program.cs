using Newtonsoft.Json;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace LoginShield;

public class LoginEvent
{
    public string IpAddress { get; set; } = "";
    public string Username { get; set; } = "";
    public bool Success { get; set; }
}

public class SecurityAnalyzer
{
    public List<string> Analyze(List<LoginEvent> events)
    {
        return events.Where(e => !e.Success)
            .GroupBy(e => e.IpAddress)
            .Where(g => g.Count() >= 3)
            .Select(g => $" BRUTE FORCE ALERT: IP {g.Key} - {g.Count()} failed logins (usernames: {string.Join(", ", g.Select(e => e.Username).Distinct())})")
            .ToList();
    }
}

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("LoginShield - Cybersecurity Brute Force Detector");
        Console.WriteLine("================================================");

        string jsonPath = args.Length > 0 ? args[0] : "logs.json";

        if (!File.Exists(jsonPath))
        {
            Console.WriteLine($"File not found: {jsonPath}");
            Console.WriteLine("Create logs.json with sample data or pass path as argument.");
            return;
        }

        try
        {
            var json = await File.ReadAllTextAsync(jsonPath);
            var events = JsonConvert.DeserializeObject<List<LoginEvent>>(json) ?? new();

            Console.WriteLine($"\n Processed {events.Count} login events");
            Console.WriteLine($" Successful: {events.Count(e => e.Success)}");
            Console.WriteLine($" Failed: {events.Count(e => !e.Success)}");

            var analyzer = new SecurityAnalyzer();
            var alerts = analyzer.Analyze(events);

            if (alerts.Any())
            {
                Console.WriteLine("\n SECURITY ALERTS:");
                Console.WriteLine(new string('=', 50));
                foreach (var alert in alerts)
                {
                    Console.WriteLine(alert);
                }

                // Save report
                Directory.CreateDirectory("output");
                await File.WriteAllTextAsync("output/report.txt", string.Join("\n", alerts));
                Console.WriteLine("\n Report saved to output/report.txt");
            }
            else
            {
                Console.WriteLine("\n No brute force attacks detected");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($" Error: {ex.Message}");
        }
    }
}