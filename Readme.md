# Todo NET8 v3 - Minimal API com autenticação

Olá Dev! 😎

Esse projeto é a continuidade do projeto [v2][v2].

Vamos implementar as funcionalidades de controle de acesso a API.

Passos:

1. CORE - Configurações de segurança.
1. CORE - Atualize o Configuration com as novas definições para envio de emails.
1. CORE - Crie um novo contexto para trabalhar com Contas de Usuário.
1. CORE - Crie VOs para tratar tipos complexos como Email e Senha.
1. CORE - Utilize o pacote [SecureIdentity][SecureIdentity] para trabalhar com Senhas.
1. CORE - Crie casos de uso para gerar um novo usuário e fazer autenticação.
1. CORE - Crie uma interface IRepository e defina as assinaturas dos métodos de acesso.
1. CORE - Crie uma interface IService e defina as assinaturas dos métodos de envio de emails.

1. INFRA - Faça o mapeamento do Usuário e o Perfil para o Banco de dados.
1. INFRA - Atualize o AppDbContext, passando os novos DbSet com Usuário e Perfil.
1. INFRA - Utilize o pacote de serviço de emails [SendGrid][SendGrid].
1. INFRA - Implemente os serviços externos (Repositórios e Envio de Emails).

1. CORE - Crie o fluxo de processo com Request, Response, Specification e Handler para manipular os dados.
1. API - Injete o repositório e serviços. Defina os endpoints com as rotas do Handler.
1. API - Atualize o appsettings.json com os API Keys.
1. API - Atualize o BuilderExtension adicionando as novas chaves e segredos da aplicação.
1. API - Execute as Migrations.

## CORE

## SEGURANÇA

1. Habilite o [.NET User Secrets][UserSecrets] para o projeto com o comando **dotnet user-secrets init**.

   Qualquer informação sensível pode ser armazenada na maquina local como JSON, sem expor na aplicação.
   Obs: Para uso com a Azure ou demais serviços na nuvem, veja a documentação especifica.

   ```csharp
    // Exemplo de uso. Podem ser criados vários segredos
    dotnet user-secrets set "SendGrid:ApiKey" "123456"

    // Estrutura do arquivo gerado
    {
      "SendGrid": {
        "ApiKey": "123456"
      }
    }
   ```

2. Atualize o arquivo de Configuração:

   ```csharp
   namespace TodoApp.Core;

   // Normalmente o valor dessas propriedades será informado no Builder da API, passando o appsettings.json
   public static class Configuration
   {
       public static DatabaseConfiguration Database { get; set; } = new();
       public static EmailConfiguration Email { get; set; } = new();
       public static SendGridConfiguration SendGrid { get; set; } = new();
       public static SecretsConfiguration Secrets { get; set; } = new();

       public class DatabaseConfiguration
       {
           public string ConnectionString { get; set; } = string.Empty;
       }

       public class EmailConfiguration
       {
           public string DefaultFromEmail { get; set; } = "test@seudominio.xyz";
           public string DefaultFromName { get; set; } = "seudominio.xyz";
       }

       public class SendGridConfiguration
       {
           // Por segurança, jamais exponha a chave da API para evitar uso indevido.
           public string ApiKey { get; set; } = string.Empty;
       }

       public class SecretsConfiguration
       {
           // Utilize o dotnet secrets ou Azure Vault para recuperar essas propriedades
           public string ApiKey { get; set; } = string.Empty;
           public string JwtPrivateKey { get; set; } = string.Empty;
           public string PasswordSaltKey { get; set; } = string.Empty;
       }
   }
   ```

Siga a estrutura de organização do AccountContext:

- **AccountContext**
  - `Entities`
  - `UseCases`
  - `ValueObjects`

## CORE - ACCOUNT CONTEXT

### CRIANDO OS OBJETOS DE VALOR

1. Crie uma classe para representar a Verificação de um serviço (Email, SMS, Outros).

   ```csharp
   namespace TodoApp.Core.Contexts.AccountContext.ValueObjects;
   public class Verification
   {
       public Verification()
       {
       }

       // Guid somente com números com 6 Dígitos
       public string Code { get; } = Guid.NewGuid().ToString("N")[..6].ToUpper();
       public DateTime? ExpiresAt { get; private set; } = DateTime.UtcNow.AddMinutes(5);
       public DateTime? VerifiedAt { get; private set; } = null;
       public bool IsActive => VerifiedAt != null && ExpiresAt == null;

       public void Verify(string code)
       {
           if (IsActive)
               throw new Exception("Este item já foi ativado");

           if (ExpiresAt < DateTime.UtcNow)
               throw new Exception("Este código já expirou");

           if (!string.Equals(code.Trim(), Code.Trim(), StringComparison.CurrentCultureIgnoreCase))
               throw new Exception("Código de verificação inválido");

           ExpiresAt = null;
           VerifiedAt = DateTime.UtcNow;
       }
   }
   ```

1. Vamos criar uma extensão no SharedContext para o usar com strings, facilitando a verificação de Hashes.

   ```csharp
   using System.Text;

   namespace TodoApp.Core.Contexts.SharedContext.Extensions;
   public static class StringExtension
   {
       public static string ToBase64(this string text)
           => Convert.ToBase64String(Encoding.ASCII.GetBytes(text));
   }
   ```

1. Agora crie uma classe para representar um Email.

   ```csharp
   using System.Text.RegularExpressions;
   using TodoApp.Core.Contexts.SharedContext.Extensions;

   namespace TodoApp.Core.Contexts.AccountContext.ValueObjects;

   // Classe definida como partial, devido o uso de Regex para validação
   public partial class Email
   {
       // Padrão regex de formatação de um email válido
       private const string Pattern = @"^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$";

       protected Email()
       {
       }

       // Construtor com validações
       public Email(string address)
       {
           if (string.IsNullOrEmpty(address))
               throw new Exception("E-mail inválido");

           Address = address.Trim().ToLower();

           if (Address.Length < 5)
               throw new Exception("E-mail inválido");

           if (!EmailRegex().IsMatch(Address))
               throw new Exception("E-mail inválido");
       }

       public string Address { get; }

       // Propriedade Hash, convertendo um email para base64 e possibilitando a comparação
       public string Hash => Address.ToBase64();
       public Verification Verification { get; private set; } = new();

       // Método para gerar um código de verificação
       public void ResendVerification()
           => Verification = new Verification();

       // Indica ao compilador como converter uma string para Email
       public static implicit operator string(Email email)
           => email.ToString();

       // Indica ao compilador como converter Email para string
       public static implicit operator Email(string address)
           => new(address);

       // Sobrescreve o ToString, retornando o endereço de email do objeto
       public override string ToString()
           => Address;

       // Método Regex para validar o endereço de email informado
       [GeneratedRegex(Pattern)]
       private static partial Regex EmailRegex();
   }
   ```

1. Crie uma classe para representar a Senha.

   ```csharp
   // Para simplificar esse VO, instale o pacote dotnet add package SecureIdentity.
   using SecureIdentity.Password;

   namespace TodoApp.Core.Contexts.AccountContext.ValueObjects;
   public class Password
   {
       protected Password() { }

       // Método construtor utilizando o SecureIdentity, convertendo a senha em texto para um Hash seguro
       public Password(string? plainTextPassword = null)
       {
           if (string.IsNullOrEmpty(plainTextPassword) || string.IsNullOrWhiteSpace(plainTextPassword))
               plainTextPassword = PasswordGenerator.Generate();

           Hash = PasswordHasher.Hash(plainTextPassword);
       }

       // Método para verificar se a senha informada é a valida
       public bool Challenge(string plainTextPassword)
           => PasswordHasher.Verify(Hash, plainTextPassword);

       public string Hash { get; } = string.Empty;

       // Gera código para recuperar a senha
       public string ResetCode { get; } = PasswordGenerator.Generate(8, false, true);
   }
   ```

### MODELANDO O USUÁRIO

1. Crie a classe User, representado um usuário.

   ```csharp
   using TodoApp.Core.Contexts.AccountContext.ValueObjects;
   using TodoApp.Core.Contexts.SharedContext.Entities;

   namespace TodoApp.Core.Contexts.AccountContext.Entities;
   public class User : Entity
   {
       // Esse construtor vazio importante na geração das Migrations do EF.
       protected User() { }

       public User(string email, string? password = null)
       {
           Email = email;
           Password = new Password(password);
       }

       public User(string name, Email email, Password password)
       {
           Name = name;
           Email = email;
           Password = password;
       }

       public string Name { get; private set; } = string.Empty;

       // Uso do Null Not, indicando que futuramente será passado valor
       public Email Email { get; private set; } = null!;
       public Password Password { get; private set; } = null!;

       // Podemos armazenar o Hash com o link da imagem com avatar do usuário
       public string Image { get; private set; } = string.Empty;

       // Lista com os perfis do usuário. Um ou mais perfis. Ex: {"estudante", "admin"}
       public List<Role> Roles { get; set; } = new();

       public void UpdateEmail(Email email)
       {
           Email = email;
       }

       public void UpdatePassword(string plainTextPassword, string code)
       {
           // Verifica se o código de reset informado é o mesmo código gerado.
           if (!string.Equals(code.Trim(), Password.ResetCode.Trim(), StringComparison.CurrentCultureIgnoreCase))
               throw new Exception("Código de restauração inválido");

           var password = new Password(plainTextPassword);
           Password = password;
       }

       public void ChangePassword(string plainTextPassword)
       {
           var password = new Password(plainTextPassword);
           Password = password;
       }
   }
   ```

### MODELANDO O PERFIL

1. Crie a classe Role, representado um perfil.

   ```csharp
   using TodoApp.Core.Contexts.SharedContext.Entities;

   namespace TodoApp.Core.Contexts.AccountContext.Entities;
   public class Role : Entity
   {
       public string Name { get; set; } = string.Empty;

       // Lista de usuários de cada perfil. Propriedade util para mapeamento no EF.
       public List<User> Users { get; set; } = new();
   }
   ```

### CASOS DE USO - CRIAÇÃO DE USUÁRIO

1. Crie as interfaces definindo os métodos para acesso a dados e serviços externos.

   ```csharp
   // Acesso ao banco de dados
   using TodoApp.Core.Contexts.AccountContext.Entities;

   namespace TodoApp.Core.Contexts.AccountContext.UseCases.Create.Contracts;

   public interface IRepository
   {
       Task<bool> AnyAsync(string email, CancellationToken cancellationToken);
       Task SaveAsync(User user, CancellationToken cancellationToken);
   }

   // Serviço para enviar Email
   using TodoApp.Core.Contexts.AccountContext.Entities;

   namespace TodoApp.Core.Contexts.AccountContext.UseCases.Create.Contracts;

   public interface IService
   {
       Task SendVerificationEmailAsync(User user, CancellationToken cancellationToken);
   }
   ```

## INFRA

### MAPEAMENTO DAS TABELAS NO BANCO DE DADOS

1. Faça a organização por contexto para representar a conta de usuário.

   ```csharp
   // Mapeando a entidade User para o banco de dados
   using Microsoft.EntityFrameworkCore;
   using Microsoft.EntityFrameworkCore.Metadata.Builders;
   using TodoApp.Core.Contexts.AccountContext.Entities;

   namespace TodoApp.Infra.Contexts.AccountContext.Mappings;
   public class UserMap : IEntityTypeConfiguration<User>
   {
       public void Configure(EntityTypeBuilder<User> builder)
       {
           builder.ToTable("User");

           // Propriedades se tornam campos da tabela User
           builder.HasKey(x => x.Id);

           builder.Property(x => x.Name)
               .HasColumnName("Name")
               .HasColumnType("NVARCHAR")
               .HasMaxLength(120)
               .IsRequired(true);

           builder.Property(x => x.Image)
               .HasColumnName("Image")
               .HasColumnType("VARCHAR")
               .HasMaxLength(255)
               .IsRequired(true);

           builder.OwnsOne(x => x.Email)
               .Property(x => x.Address)
               .HasColumnName("Email")
               .IsRequired(true);

           builder.OwnsOne(x => x.Email)
               .OwnsOne(x => x.Verification)
               .Property(x => x.Code)
               .HasColumnName("EmailVerificationCode")
               .IsRequired(true);

           builder.OwnsOne(x => x.Email)
               .OwnsOne(x => x.Verification)
               .Property(x => x.ExpiresAt)
               .HasColumnName("EmailVerificationExpiresAt")
               .IsRequired(false);

           builder.OwnsOne(x => x.Email)
               .OwnsOne(x => x.Verification)
               .Property(x => x.VerifiedAt)
               .HasColumnName("EmailVerificationVerifiedAt")
               .IsRequired(false);

           builder.OwnsOne(x => x.Email)
               .OwnsOne(x => x.Verification)
               .Ignore(x => x.IsActive);

           builder.OwnsOne(x => x.Password)
               .Property(x => x.Hash)
               .HasColumnName("PasswordHash")
               .IsRequired();

           builder.OwnsOne(x => x.Password)
               .Property(x => x.ResetCode)
               .HasColumnName("PasswordResetCode")
               .IsRequired();

           // Aqui é gerada uma tabela intermediária UserRole para relacionar muitos Users com muitos Roles
           builder
               .HasMany(x => x.Roles)
               .WithMany(x => x.Users)
               .UsingEntity<Dictionary<string, object>>(
                   "UserRole",
                   role => role
                       .HasOne<Role>()
                       .WithMany()
                       .HasForeignKey("RoleId")
                       .OnDelete(DeleteBehavior.Cascade),
                   user => user
                       .HasOne<User>()
                       .WithMany()
                       .HasForeignKey("UserId")
                       .OnDelete(DeleteBehavior.Cascade));
       }
   }
   ```

1. Agora é a vez de mapear os Perfis. Crie um RoleMap

   ```csharp
   using Microsoft.EntityFrameworkCore;
   using Microsoft.EntityFrameworkCore.Metadata.Builders;
   using TodoApp.Core.Contexts.AccountContext.Entities;

   namespace TodoApp.Infra.Contexts.AccountContext.Mappings;
   public class RoleMap : IEntityTypeConfiguration<Role>
   {
       public void Configure(EntityTypeBuilder<Role> builder)
       {
           builder.ToTable("Role");
           builder.HasKey(x => x.Id);
           builder.Property(x => x.Name)
               .HasColumnName("Name")
               .HasColumnType("NVARCHAR")
               .HasMaxLength(120)
               .IsRequired(true);

        // Veja que o relacionamento das tabelas só precisa ser declarado em um dos mapeamentos.
       }
   }
   ```

### ATUALIZANDO O AppDbContext

1. Com o mapeamento criado, atualize o AppDbContext criando novos DbSet.

   ```csharp
   using Microsoft.EntityFrameworkCore;
   using TodoApp.Core.Contexts.AccountContext.Entities;
   using TodoApp.Core.Contexts.TodoContext.Entities;
   using TodoApp.Infra.Contexts.AccountContext.Mappings;
   using TodoApp.Infra.Contexts.TodoContext.Mappings;

   namespace TodoApp.Infra.Data;

   public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
   {
     public DbSet<Todo> Todos { get; set; } = null!;

     // Novos DbSet para Usuários e Perfis
     public DbSet<User> Users { get; set; } = null!;
     public DbSet<Role> Roles { get; set; } = null!;

     protected override void OnModelCreating(ModelBuilder modelBuilder)
     {
       modelBuilder.ApplyConfiguration(new TodoMap());

       // Ao executar a Migration, aplica a configuração com mapeamento
       modelBuilder.ApplyConfiguration(new UserMap());
       modelBuilder.ApplyConfiguration(new RoleMap());
     }
   }
   ```

### IMPLEMENTE OS MÉTODOS PARA USO DOS REPOSITÓRIOS E SERVIÇOS EXTERNOS

```csharp
using Microsoft.EntityFrameworkCore;
using TodoApp.Core.Contexts.AccountContext.Entities;
using TodoApp.Core.Contexts.AccountContext.UseCases.Create;
using TodoApp.Infra.Data;

namespace TodoApp.Infra.Contexts.AccountContext.UseCases.Create;
public class Repository(AppDbContext context) : IRepository
{
    private readonly AppDbContext _context = context;

    public async Task<bool> AnyAsync(string email, CancellationToken cancellationToken)
        => await _context
            .Users
            .AsNoTracking()
            .AnyAsync(x => x.Email.Address == email, cancellationToken: cancellationToken);

    public async Task SaveAsync(User user, CancellationToken cancellationToken)
    {
        await _context.Users.AddAsync(user, cancellationToken);
        await _context.SaveChangesAsync(cancellationToken);
    }
}
```

### IMPLEMENTE O SERVIÇO DE ENVIO DE EMAILS

1. Aqui vamos usar o SendGrid, adicione o pacote ao projeto de Infra:

   ```csharp
   dotnet add package SendGrid
   ```

   E agora implemente o serviço:

   ```csharp
   using SendGrid;
   using SendGrid.Helpers.Mail;
   using TodoApp.Core;
   using TodoApp.Core.Contexts.AccountContext.Entities;
   using TodoApp.Core.Contexts.AccountContext.UseCases.Create;

   namespace TodoApp.Infra.Contexts.AccountContext.UseCases.Create;
   public class Service : IService
   {
       public async Task SendVerificationEmailAsync(User user, CancellationToken cancellationToken)
       {
           var client = new SendGridClient(Configuration.SendGrid.ApiKey);
           var from = new EmailAddress(Configuration.Email.DefaultFromEmail, Configuration.Email.DefaultFromName);
           const string subject = "Verifique sua conta";
           var to = new EmailAddress(user.Email, user.Name);
           var content = $"Código {user.Email.Verification.Code}";
           var msg = MailHelper.CreateSingleEmail(from, to, subject, content, content);
           await client.SendEmailAsync(msg, cancellationToken);
       }
   }
   ```

## CORE

### FLUXO DE PROCESSO PARA CRIAR UM USUÁRIO

1. Crie o request, passando o Nome, Email e a Senha.

   ```csharp
   using MediatR;

   namespace TodoApp.Core.Contexts.AccountContext.UseCases.Create;
   public record Request(
       string Name,
       string Email,
       string Password
   ) : IRequest<Response>;
   ```

1. Crie o response, para retornar o usuário.

   ```csharp
   using Flunt.Notifications;

   namespace TodoApp.Core.Contexts.AccountContext.UseCases.Create;
   public class Response : SharedContext.UseCases.Response
   {
       protected Response() { }

       public Response(
           string message,
           int status,
           IEnumerable<Notification>? notifications = null)
       {
           Message = message;
           Status = status;
           Notifications = notifications;
       }

       public Response(string message, ResponseData data)
       {
           Message = message;
           Status = 201;
           Notifications = null;
           Data = data;
       }

       public ResponseData? Data { get; set; }
   }

   public record ResponseData(Guid Id, string Name, string Email);
   ```

1. Agora crie uma especificação, que será usada para validar a criação do usuário.

   ```csharp
   using Flunt.Notifications;
   using Flunt.Validations;

   namespace TodoApp.Core.Contexts.AccountContext.UseCases.Create;
   public static class Specification
   {
       public static Contract<Notification> Ensure(Request request)
           => new Contract<Notification>()
               .Requires()
               .IsLowerThan(request.Name.Length, 160, "Name", "O nome deve conter menos que 160 caracteres")
               .IsGreaterThan(request.Name.Length, 3, "Name", "O nome deve conter mais que 3 caracteres")
               .IsLowerThan(request.Password.Length, 40, "Password", "A senha deve conter menos que 40 caracteres")
               .IsGreaterThan(request.Password.Length, 8, "Password", "A senha deve conter mais que 8 caracteres")
               .IsEmail(request.Email, "Email", "E-mail inválido");
   }
   ```

1. E agora o Handler, para manipular o fluxo de criação do usuário.

```csharp
using MediatR;
using TodoApp.Core.Contexts.AccountContext.Entities;
using TodoApp.Core.Contexts.AccountContext.UseCases.Create.Contracts;
using TodoApp.Core.Contexts.AccountContext.ValueObjects;

namespace TodoApp.Core.Contexts.AccountContext.UseCases.Create;

// Serviços externos injetados
public class Handler(IRepository repository, IService service) : IRequestHandler<Request, Response>
{
    private readonly IRepository _repository = repository;
    private readonly IService _service = service;

    public async Task<Response> Handle(
        Request request,
        CancellationToken cancellationToken)
    {
        #region 01. Valida a requisição

        try
        {
            // Testa as especificações definidas. Aqui usamos o fail fast validation.
            var specification = Specification.Ensure(request);
            if (!specification.IsValid)
                return new Response("Requisição inválida", 400, specification.Notifications);
        }
        catch
        {
            return new Response("Não foi possível validar sua requisição", 500);
        }

        #endregion

        #region 02. Gera os Objetos

        Email email;
        Password password;
        User user;

        try
        {
            email = new Email(request.Email);
            password = new Password(request.Password);
            user = new User(request.Name, email, password);
        }
        catch (Exception ex)
        {
            return new Response(ex.Message, 400);
        }

        #endregion

        #region 03. Verifica se o usuário existe no banco

        try
        {
            var exists = await _repository.AnyAsync(request.Email, cancellationToken);
            if (exists)
                return new Response("Este E-mail já está em uso", 400);
        }
        catch
        {
            return new Response("Falha ao verificar E-mail cadastrado", 500);
        }

        #endregion

        #region 04. Persiste os dados

        try
        {
            await _repository.SaveAsync(user, cancellationToken);
        }
        catch
        {
            return new Response("Falha ao persistir dados", 500);
        }

        #endregion

        #region 05. Envia E-mail de ativação

        try
        {
            await _service.SendVerificationEmailAsync(user, cancellationToken);
        }
        catch
        {
            // Do nothing
        }

        #endregion

        // Caso esteja tudo ok, gera uma nova conta de usuário
        return new Response(
            "Conta criada",
            new ResponseData(user.Id, user.Name, user.Email));
    }
}
```

1. Repita o mesmo processo para o caso de uso de autenticação.

## API

### INJETANDO REPOSITÓRIO E ENDPOINTS

1. Crie um AccountContextExtension. Faça o processo de injeção de serviços externos e rotas.

```csharp
using MediatR;

namespace TodoApp.Api;

public static class AccountContextExtension
{
    public static void AddAccountContext(this WebApplicationBuilder builder)
    {
        #region Create

        builder.Services.AddTransient<
            TodoApp.Core.Contexts.AccountContext.UseCases.Create.Contracts.IRepository,
            TodoApp.Infra.Contexts.AccountContext.UseCases.Create.Repository>();

        builder.Services.AddTransient<
            TodoApp.Core.Contexts.AccountContext.UseCases.Create.Contracts.IService,
            TodoApp.Infra.Contexts.AccountContext.UseCases.Create.Service>();

        #endregion

        #region Authenticate

        builder.Services.AddTransient<
            TodoApp.Core.Contexts.AccountContext.UseCases.Authenticate.Contracts.IRepository,
            TodoApp.Infra.Contexts.AccountContext.UseCases.Authenticate.Repository>();

        #endregion
    }

    public static void MapAccountEndpoints(this WebApplication app)
    {
        #region Create

        app.MapPost("api/v1/users", async (
            TodoApp.Core.Contexts.AccountContext.UseCases.Create.Request request,
            IRequestHandler<
                TodoApp.Core.Contexts.AccountContext.UseCases.Create.Request,
                TodoApp.Core.Contexts.AccountContext.UseCases.Create.Response> handler) =>
        {
            var result = await handler.Handle(request, new CancellationToken());
            return result.IsSuccess
                ? Results.Created($"api/v1/users/{result.Data?.Id}", result)
                : Results.Json(result, statusCode: result.Status);
        });

        #endregion

        #region Authenticate

        app.MapPost("api/v1/authenticate", async (
            TodoApp.Core.Contexts.AccountContext.UseCases.Authenticate.Request request,
            IRequestHandler<
                TodoApp.Core.Contexts.AccountContext.UseCases.Authenticate.Request,
                TodoApp.Core.Contexts.AccountContext.UseCases.Authenticate.Response> handler) =>
        {
            var result = await handler.Handle(request, new CancellationToken());
            if (!result.IsSuccess)
                return Results.Json(result, statusCode: result.Status);

            if (result.Data is null)
                return Results.Json(result, statusCode: 500);

            // Vamos criar o JwtExtension na sequencia do passo a passo
            result.Data.Token = JwtExtension.Generate(result.Data);
            return Results.Ok(result);
        });

        #endregion
    }
}
```

1. Crie o JwtExtension. Primeiro, adicione o pacote para habilitar a autenticação:

   ```csharp
   dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
   ```

   ```csharp
   using System.IdentityModel.Tokens.Jwt;
   using System.Security.Claims;
   using System.Text;
   using Microsoft.IdentityModel.Tokens;
   using TodoApp.Core;
   using TodoApp.Core.Contexts.AccountContext.UseCases.Authenticate;

   namespace TodoApp.Api.Extensions;
   public static class JwtExtension
   {
       public static string Generate(ResponseData data)
       {
           var handler = new JwtSecurityTokenHandler();
           var key = Encoding.ASCII.GetBytes(Configuration.Secrets.JwtPrivateKey);
           var credentials = new SigningCredentials(
               new SymmetricSecurityKey(key),
               SecurityAlgorithms.HmacSha256Signature); // Segurança SHA-256

           var tokenDescriptor = new SecurityTokenDescriptor
           {
               Subject = GenerateClaims(data),
               Expires = DateTime.UtcNow.AddHours(8), // Token válido por 8 horas
               SigningCredentials = credentials,
           };
           var token = handler.CreateToken(tokenDescriptor);
           return handler.WriteToken(token);
       }

       private static ClaimsIdentity GenerateClaims(ResponseData user)
       {
           // Insere no token informações de identificação do usuário
           var ci = new ClaimsIdentity();
           ci.AddClaim(new Claim("Id", user.Id));
           ci.AddClaim(new Claim(ClaimTypes.GivenName, user.Name));
           ci.AddClaim(new Claim(ClaimTypes.Name, user.Email));
           foreach (var role in user.Roles)
               ci.AddClaim(new Claim(ClaimTypes.Role, role));

           return ci;
       }
   }
   ```

2. Crie uma extensão para as afirmações (Claims), tornando mais fácil recuperar as informações do usuário.

   ```csharp
   using System.Security.Claims;

   namespace TodoApp.Api.Extensions;
   public static class ClaimsPrincipalExtension
   {
       public static string Id(this ClaimsPrincipal user)
           => user.Claims.FirstOrDefault(c => c.Type == "Id")?.Value ?? string.Empty;

       public static string Name(this ClaimsPrincipal user)
           => user.Claims.FirstOrDefault(c => c.Type == ClaimTypes.GivenName)?.Value ?? string.Empty;

       public static string Email(this ClaimsPrincipal user)
           => user.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value ?? string.Empty;
   }
   ```

3. Atualize o BuilderExtension, informando as novas configurações e adicionando a autenticação Jwt.

   ```csharp
   using System.Text;
   using Microsoft.AspNetCore.Authentication.JwtBearer;
   using Microsoft.EntityFrameworkCore;
   using Microsoft.IdentityModel.Tokens;
   using TodoApp.Core;
   using TodoApp.Infra.Data;

   namespace TodoApp.Api.Extensions;
   public static class BuilderExtension
   {
       // Recupera as informações do appsettings.json e carrega ao inicializar a API
       public static void AddConfiguration(this WebApplicationBuilder builder)
       {
           Configuration.Database.ConnectionString =
               builder.Configuration.GetConnectionString("DefaultConnection") ?? string.Empty;

           Configuration.Secrets.ApiKey =
               builder.Configuration.GetSection("Secrets").GetValue<string>("ApiKey") ?? string.Empty;
           Configuration.Secrets.JwtPrivateKey =
               builder.Configuration.GetSection("Secrets").GetValue<string>("JwtPrivateKey") ?? string.Empty;
           Configuration.Secrets.PasswordSaltKey =
               builder.Configuration.GetSection("Secrets").GetValue<string>("PasswordSaltKey") ?? string.Empty;

           Configuration.SendGrid.ApiKey =
               builder.Configuration.GetSection("SendGrid").GetValue<string>("ApiKey") ?? string.Empty;

           Configuration.Email.DefaultFromName =
               builder.Configuration.GetSection("Email").GetValue<string>("DefaultFromName") ?? string.Empty;
           Configuration.Email.DefaultFromEmail =
               builder.Configuration.GetSection("Email").GetValue<string>("DefaultFromEmail") ?? string.Empty;
       }

       public static void AddDatabase(this WebApplicationBuilder builder)
       {
           builder.Services.AddDbContext<AppDbContext>(x =>
               x.UseSqlite(
                   Configuration.Database.ConnectionString,
                   b => b.MigrationsAssembly("TodoApp.Api")));
       }

       public static void AddJwtAuthentication(this WebApplicationBuilder builder)
       {
           builder.Services
               .AddAuthentication(x =>
               {
                   x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                   x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
               }).AddJwtBearer(x =>
               {
                   x.RequireHttpsMetadata = false;
                   x.SaveToken = true;
                   x.TokenValidationParameters = new TokenValidationParameters
                   {
                       IssuerSigningKey = new SymmetricSecurityKey(
                            Encoding.ASCII.GetBytes(Configuration.Secrets.JwtPrivateKey)),
                       ValidateIssuer = false,
                       ValidateAudience = false
                   };
               });
           builder.Services.AddAuthorization();
       }

       public static void AddMediator(this WebApplicationBuilder builder)
       {
           builder.Services.AddMediatR(x
               => x.RegisterServicesFromAssembly(typeof(Configuration).Assembly));
       }
   }
   ```

### APP SETTINGS

1. Configure o arquivo appsettings.json da Api com as informações que serão carregadas no BuilderExtension:

   ```csharp
   {
     "ConnectionStrings": {
       "DefaultConnection": "Data Source=Todo.db;"
     },
     "Secrets": {
       "ApiKey": "MinhaChaveDefinida",
       "JwtPrivateKey": "MinhaChaveDefinidaJwt",
       "PasswordSaltKey": "MinhaSenhaSecreta"
     },
     "SendGrid": {
       "ApiKey": "MinhaChaveFornecidaPeloSendGrid"
     },
     "Email": {
       "DefaultFromName": "Responsável pela Mensagem",
       "DefaultFromEmail": "seuemail@seudominio.xyz"
     }
   }
   ```

Obs: Você pode utilizar o comando no terminal **New-Guid** para gerar chaves aleatórias (apenas para testes).

### API - ATUALIZANDO BUILDER

1. Para fechar a atualização da estrutura, atualize o Program.cs da API:

   ```csharp
   using TodoApp.Api;
   using TodoApp.Api.Extensions;

   var builder = WebApplication.CreateBuilder(args);
   builder.AddConfiguration();
   builder.AddDatabase();
   builder.AddJwtAuthentication(); // Adicionada autenticação jwt(jót)
   builder.AddTodoContext();
   builder.AddAccountContext(); // Injeção das contas de usuário

   builder.AddMediator();

   var app = builder.Build();
   app.MapTodoEndpoints();
   app.MapAccountEndpoints(); // Novas rotas para contas de usuário

   app.Run();
   ```

### API - Atualizando o Banco de dados

1. Com a configuração aplicada, utilize os comandos abaixo para refletir as alterações na aplicação no Banco de Dados.

   ```csharp
   // Gera uma migração com a adição de Contas de Usuários
   dotnet ef migrations add AccountContext

   // Atualiza o banco com a nova estrutura de tabelas
   dotnet ef database update
   ```

### Rodando a Web API

Testando a rota de criação de usuário:

![CreateUserRoute][CreateUserRoute]

Registro gerado no banco:

![CreatedUserOnDb][CreatedUserOnDb]

Testando a autenticação do usuário (gera erro, pois não foi desenvolvido link para ativação por email).

![AuthError][AuthError]

Após atualizar os campos diretamente no banco de dados, informando o email como verificado e removida a informação de expiração.

![AuthOK][AuthOK]

### Por enquanto, é isso aí. Bons estudos e bons códigos! 👍

[v2]: https://github.com/thiagokj/TodoNet8v2
[SecureIdentity]: https://github.com/andrebaltieri/SecureIdentity
[SendGrid]: https://sendgrid.com/
[UserSecrets]: https://learn.microsoft.com/pt-br/aspnet/core/security/app-secrets?view=aspnetcore-8.0&tabs=windows
[CreateUserRoute]: Doc/endpoint-test.png
[CreatedUserOnDb]: Doc/db-tuple.png
[AuthError]: Doc/endpoint-test-auth-error.png
[AuthOK]: Doc/auth-ok.png
