using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace frontend.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;

        public IndexModel(ILogger<IndexModel> logger)
        {
            _logger = logger;
        }

        public WeatherForecast[] Forecasts { get; set; }

        public async Task OnGet([FromServices] WeatherClient client)
        {
            Forecasts = await client.GetWeatherAsync();
        }
    }
}
