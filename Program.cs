using JwtNetApi;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(opts =>

        opts.TokenValidationParameters = new()
        {
            ValidateAudience = false,
            ValidateIssuer = false,
            IssuerSigningKey = new SymmetricSecurityKey
            (Encoding.ASCII.GetBytes(builder.Configuration.GetConnectionString("JwtSecret"))),
        }
    );

builder.Services.AddAuthorization();

builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen(opts =>
{
    opts.SwaggerDoc("v1", new() { Title = "Json Web Token", Version = "v1" });

    opts.AddSecurityDefinition("bearer", new()
    {
        Name = "JWT Authorization",
        Description = "Enter token",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        BearerFormat = "JWT",
        Scheme = "bearer"
    });

    opts.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type=ReferenceType.SecurityScheme,
                    Id="bearer"
                }
            },
            Array.Empty<string>() // No scope
        }
    });
});

var app = builder.Build();

app.UseAuthentication().UseAuthorization();

app.UseSwagger().UseSwaggerUI();

app.MapPost("/token", (User user) => new JwtService().GenerateToken(user, builder.Configuration.GetConnectionString("JwtSecret")));
app.MapGet("/sign-in", () => "Hello World!").RequireAuthorization();

app.Run();
