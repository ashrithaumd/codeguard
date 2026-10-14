// Planted: a query-string value becomes part of a shell command line.
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace Reports.Controllers;

[ApiController]
[Route("api/reports")]
public class ExportController : ControllerBase
{
    [HttpPost("{id:int}/pdf")]
    public IActionResult ExportPdf(int id, [FromQuery] string fileName)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "/bin/sh",
            Arguments = $"-c \"wkhtmltopdf http://localhost:5000/reports/{id} /tmp/{fileName}.pdf\"",
            RedirectStandardError = true,
        };
        using var proc = Process.Start(psi)!;
        proc.WaitForExit();
        if (proc.ExitCode != 0)
        {
            return StatusCode(500, proc.StandardError.ReadToEnd());
        }
        return PhysicalFile($"/tmp/{fileName}.pdf", "application/pdf");
    }
}
