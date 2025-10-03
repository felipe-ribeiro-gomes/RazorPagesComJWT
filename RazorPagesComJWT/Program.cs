using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

var key = "sua-chave-secreta-muito-segura-e-complexa"; // Guarde em config segura!

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
 {
     options.TokenValidationParameters = new TokenValidationParameters
     {
         ValidateIssuer = true,
         ValidateAudience = true,
         ValidateLifetime = true,
         ValidateIssuerSigningKey = true,
         ValidIssuer = "sua-aplicacao",
         ValidAudience = "seus-usuarios",
         IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key))
     };
     // Lê token do cookie "AuthToken"
     options.Events = new JwtBearerEvents
     {
         OnMessageReceived = context =>
         {
             var token = context.Request.Cookies["AuthToken"];
             if (!string.IsNullOrEmpty(token))
             {
                 context.Token = token;
             }
             return Task.CompletedTask;
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
