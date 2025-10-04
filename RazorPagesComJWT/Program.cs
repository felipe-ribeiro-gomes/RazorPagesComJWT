using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using RazorPagesComJWT.Configurations;
using System.Security.Cryptography;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<JWT>(builder.Configuration.GetSection("JWT"));

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
 {
     var _jwt = builder.Configuration.GetSection("JWT").Get<JWT>();

     //Carrega a chave simétrica (implementação mais fácil, porém menos seguro em ambientes onde todos os desenvolvedores precisam conhecer a chave para desenvolver seus sistemas que usam token de um sistema central de autenticação)
     //se o seu sistema for responsável por gerar e consumir o token, e um só desenvolvedor for ficar sabendo da chave, não tem problema
     var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.SymmetricSecurityKey));

     // Carregue a chave pública (implementação mais dificil, porém mais seguro porque só precisa compartilhar a chave pública com os desenvolvedores de sistemas que usam token de um sistema central de autenticação)
     // a chave privada somente é usada pelo sistema que gera o token, ou seja, muito menos gente sabendo da chave, fica mais seguro. chave pública todo mundo pode saber, não tem problema
     string publicKeyBase64 = _jwt.RSAPublicKey;

     // Converte a chave pública para RSA
     var publicKeyBytes = Convert.FromBase64String(publicKeyBase64);
     RSA rsa = RSA.Create();
     rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
     var rsaSecurityKey = new RsaSecurityKey(rsa);

     options.TokenValidationParameters = new TokenValidationParameters
     {
         ValidateIssuer = true,
         ValidateAudience = true,
         ValidateLifetime = true,
         ValidateIssuerSigningKey = true,
         ValidIssuer = _jwt.Issuer,
         ValidAudience = _jwt.Audience,
         //IssuerSigningKey = symmetricSecurityKey,
         IssuerSigningKey = rsaSecurityKey,
         ClockSkew = TimeSpan.Zero, //tolerância zero para o tempo de vida do token
     };

     options.Events = new JwtBearerEvents
     {
         // Lê token do cookie "AuthToken"
         OnMessageReceived = context =>
         {
             var token = context.Request.Cookies["AuthToken"];
             if (!string.IsNullOrEmpty(token))
             {
                 context.Token = token;
             }
             return Task.CompletedTask;
         },

         //Intercepta HTTP 401. Caso ocorra, redireciona para a página de Login
         OnChallenge = async context =>
         {
             context.HandleResponse();
             if (context.Request.Method == "GET")
             {
                 context.Response.Redirect("/Login");
             }
             else
             {
                 context.Response.StatusCode = 401;
                 context.Response.ContentType = "application/json";
                 var result = System.Text.Json.JsonSerializer.Serialize(new { message = "Não autorizado" });
                 await context.Response.WriteAsync(result);
             }
         }
     };
 });

// Add services to the container.
builder.Services.AddRazorPages();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication(); // Importante: autenticação antes da autorização
app.UseAuthorization();

app.MapRazorPages();

app.Run();
