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

     //Carrega a chave sim�trica (implementa��o mais f�cil, por�m menos seguro em ambientes onde todos os desenvolvedores precisam conhecer a chave para desenvolver seus sistemas que usam token de um sistema central de autentica��o)
     //se o seu sistema for respons�vel por gerar e consumir o token, e um s� desenvolvedor for ficar sabendo da chave, n�o tem problema
     var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.SymmetricSecurityKey));

     // Carregue a chave p�blica (implementa��o mais dificil, por�m mais seguro porque s� precisa compartilhar a chave p�blica com os desenvolvedores de sistemas que usam token de um sistema central de autentica��o)
     // a chave privada somente � usada pelo sistema que gera o token, ou seja, muito menos gente sabendo da chave, fica mais seguro. chave p�blica todo mundo pode saber, n�o tem problema
     string publicKeyBase64 = _jwt.RSAPublicKey;

     // Converte a chave p�blica para RSA
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
         ClockSkew = TimeSpan.Zero, //toler�ncia zero para o tempo de vida do token
     };

     options.Events = new JwtBearerEvents
     {
         // L� token do cookie "AuthToken"
         OnMessageReceived = context =>
         {
             var token = context.Request.Cookies["AuthToken"];
             if (!string.IsNullOrEmpty(token))
             {
                 context.Token = token;
             }
             return Task.CompletedTask;
         },

         //Intercepta HTTP 401. Caso ocorra, redireciona para a p�gina de Login
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
                 var result = System.Text.Json.JsonSerializer.Serialize(new { message = "N�o autorizado" });
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

app.UseAuthentication(); // Importante: autentica��o antes da autoriza��o
app.UseAuthorization();

app.MapRazorPages();

app.Run();
