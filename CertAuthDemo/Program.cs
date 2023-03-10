using CertAuthDemo.Services;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.OpenApi.Models;
using System.Security.Claims;
using System.Text.Json.Serialization;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers().AddJsonOptions(config =>
{
    config.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;
});
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "WebApi v1",
        Version = "v1",
        Description = "This is a demo API"
    });
    //options.SwaggerDoc("v2", new OpenApiInfo
    //{
    //    Title = "WebApi v2",
    //    Version = "v2",
    //    Description = "This is a demo API"
    //});
    options.AddSecurityDefinition("ApiKey", new OpenApiSecurityScheme
    {
        Name = "X-API-KEY",
        Type = SecuritySchemeType.ApiKey,
        In = ParameterLocation.Header,
        Description = "API key authorization header",
    });
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "ApiKey"
                }
            },
            new string[] {}
        }
    });
});
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = CertificateAuthenticationDefaults.AuthenticationScheme;
})
.AddCertificate(options =>
{
    options.AllowedCertificateTypes = CertificateTypes.All;
    options.Events = new CertificateAuthenticationEvents
    {
        OnCertificateValidated = context =>
        {
            ICertificateValidationService validService = context.HttpContext.RequestServices.GetRequiredService<ICertificateValidationService>();

            if (validService.ValidateCertificate(context.ClientCertificate))
            {
                Claim[] claims = new[]
                {
                    new Claim(
                        ClaimTypes.NameIdentifier,
                        context.ClientCertificate.Subject,
                        ClaimValueTypes.String,
                        context.Options.ClaimsIssuer),
                    new Claim(
                        ClaimTypes.Name,
                        context.ClientCertificate.Subject,
                        ClaimValueTypes.String,
                        context.Options.ClaimsIssuer)
                };

                context.Principal = new ClaimsPrincipal(
                    new ClaimsIdentity(claims, context.Scheme.Name));
                context.Success();
                return Task.CompletedTask;
            }

            context.Fail("Certifcate validation failure");
            return Task.CompletedTask;
        }
    };
});
builder.Services.AddApiVersioning(options =>
{
    options.AssumeDefaultVersionWhenUnspecified = true;
    options.DefaultApiVersion = new(1, 0);
    options.ReportApiVersions = true;
});
builder.Services.AddVersionedApiExplorer(options =>
{
    options.GroupNameFormat = "'v'VVV";
    options.SubstituteApiVersionInUrl = true;
});
builder.Services.AddCors(policy =>
{
    policy.AddPolicy("OpenCorsPolicy", options =>
        options
            .AllowAnyOrigin()
            .AllowAnyHeader()
            .AllowAnyMethod());
});
builder.Services.Configure<KestrelServerOptions>(options =>
{
    options.ConfigureHttpsDefaults(options =>
    {
        options.ClientCertificateMode = Microsoft.AspNetCore.Server.Kestrel.Https.ClientCertificateMode.AllowCertificate;
    });
});
builder.Services.AddTransient<ICertificateValidationService, CertificateValidationService>();
builder.Services.AddHealthChecks();
WebApplication app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        // options.SwaggerEndpoint("/swagger/v2/swagger.json", "WebApi v2");
        options.SwaggerEndpoint("/swagger/v1/swagger.json", "WebApi v1");
        options.EnableTryItOutByDefault();
        options.ConfigObject.AdditionalItems["syntaxHighlight"] = new Dictionary<string, object>
        {
            ["activated"] = false
        };
    });
}

app.UseHttpsRedirection();
app.UseCors("OpenCorsPolicy");
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.MapHealthChecks("/api/health").AllowAnonymous();
app.Run();
