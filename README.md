# Resumo: Single Sign-On com Ping Federate

## Visão geral do mecanismo

O SSO foi implementado usando um **Auth Provider customizado** do Salesforce, que integra com o Ping Federate via OAuth 2.0 / OpenID Connect. O fluxo segue o padrão **Authorization Code**, com extensões para atender requisitos específicos do IdP (IdP = Identity Provider).

### Fluxo em alto nível

```
┌─────────────┐                    ┌─────────────────┐                    ┌──────────────────┐
│   Usuário   │                    │   Salesforce    │                    │  Ping Federate   │
│  (Browser)  │                    │  Auth Provider  │                    │    (IdP/OAuth)   │
└──────┬──────┘                    └────────┬────────┘                    └────────┬─────────┘
       │                                     │                                     │
       │  1. Acessa URL de login SSO         │                                     │
       │     /services/auth/sso/Ping_Federate_POC                                  │
       │────────────────────────────────────>                                      │
       │                                     │                                     │
       │  2. Redirect para Authorize URL     │                                     │
       │<────────────────────────────────────│                                     │
       │                                     │                                     │
       │  3. Redireciona usuário ao IdP      │                                     │
       │───────────────────────────────────────-──────────────────────────────────>│
       │                                     │                                     │
       │  4. Usuário autentica no IdP        │                                     │
       │                                     │                                     │
       │  5. Redirect com authorization code │                                     │
       │<───────────────────────────────────────-──────────────────────────────────│
       │                                     │                                     │
       │  6. Callback para Salesforce        │                                     │
       │────────────────────────────────────>                                      │
       │                                     │  7. Troca code por tokens           │
       │                                     │     (POST com app-key no header)    │
       │                                     │────────────────────────────────────>│
       │                                     │<────────────────────────────────────│
       │                                     │  access_token, id_token, refresh    │
       │                                     │                                     │
       │                                     │  8. getUserInfo: extrai sub do      │
       │                                     │     id_token (JWT)                  │
       │                                     │                                     │
       │                                     │  9. RegistrationHandler: busca User │
       │                                     │     por FederationIdentifier = sub  │
       │                                     │     (ou cria link se já logou antes)│
       │                                     │                                     │
       │  10. Login concluído – usuário logado                                     │
       │<────────────────────────────────────│                                     │
```

### Pontos principais

1. **Auth Provider Custom**  
   O tipo de Auth Provider é **Custom**, em vez de OIDC padrão, para permitir o envio do header `app-key` exigido pelo API Gateway nas requisições de token.

2. **User matching via FederationIdentifier**  
   O claim `sub` do `id_token` (JWT) corresponde ao `FederationIdentifier` do usuário no Salesforce. Na primeira autenticação, o Registration Handler localiza o usuário por esse campo e retorna o registro para que o framework crie o **Third-Party Account Link**. Nas autenticações seguintes, o framework usa esse link e chama `updateUser`.

3. **Sem JIT (Just-in-Time) Provisioning**  
   Novos usuários não são criados automaticamente. Apenas usuários já existentes com `FederationIdentifier` preenchido podem fazer login.

4. **PKCE preparado**  
   O plugin está preparado para PKCE (code_verifier / code_challenge), com suporte a cache para armazenar o `code_verifier` entre o fluxo de autorização e o callback. O PKCE está habilitado no Auth Provider; o uso efetivo depende da configuração do IdP.

5. **Autenticação no token endpoint**  
   O token é solicitado com `Authorization: Basic base64(client_id:client_secret)` e o header customizado `app-key`.

---

## Passos dados no estabelecimento da POC

1. **Criação e configuração de um Auth Provider padrão OpenID Connect** – funcionou o primeiro passo de autorização, mas ao batermos no endpoint de token verificamos que o Ping Federate não estava exposto à internet.
1. **Exposição do endpoint de token via API Gateway** – o Ping Federate passou a ser acessível pela internet através do Gateway.
1. **Criação de um Custom Auth Provider (plugin Apex)** – o Gateway exige o header customizado app-key no token endpoint para autenticar a Salesforce, o que não é suportado pelo Auth Provider padrão OIDC. Foi necessário desenvolver um plugin Apex para incluir esse header.
1. **Ajuste do endpoint na Salesforce para o API Gateway** – após apontar para o Gateway, surgiu o erro invalid_credentials.
1. **Adição de Basic Authentication no header do request** – resolvido o erro de credenciais, apareceu um erro de PKCE: o Gateway não encaminhava o parâmetro code_verifier do body para o Ping Federate.
1. **Desabilitação do PKCE** – com a desabilitação do check conseguimos obter access_token e id_token, mas o sub do id_token não correspondia ao User.FederationIdentifier no Salesforce.
1. **Ajuste da claim sub pelo time do Ping Federate** – o IdP passou a retornar o sub correto, alinhado ao FederationIdentifier dos usuários no Salesforce.
1. **SSO estabelecido com sucesso.**
1. **Refinamento do Registration Handler** – na primeira autenticação, o framework não encontrava usuário por falta de Third-Party Account Link. O Registration Handler foi ajustado para, em createUser, localizar o usuário existente por FederationIdentifier e retorná-lo, permitindo que o framework criasse o link e o login funcionasse.

## Componentes gerados

### 1. Classes Apex

| Arquivo | Descrição |
|--------|-----------|
| `PingFederateAuthProviderPlugin.cls` | Plugin customizado que estende `Auth.AuthProviderPluginClass`. Implementa `initiate`, `handleCallback`, `getUserInfo`, `refresh`. Responsável pelo fluxo OAuth, envio do header `app-key`, decodificação do `id_token` e extração do `sub`. |
| `PingFederatePOCRegistrationHandler.cls` | Implementa `Auth.RegistrationHandler`. Sem JIT: `canCreateUser` retorna `true` apenas para permitir a busca de usuário existente. `createUser` localiza o User por `FederationIdentifier` e o retorna para o framework criar o link; `updateUser` atualiza dados do usuário em logins subsequentes. |

### 2. Custom Metadata Type

| Arquivo | Descrição |
|--------|-----------|
| `objects/PingFederateAuthConfig__mdt/` | Custom Metadata Type **PingFederateAuthConfig** com campos: Consumer Key, Consumer Secret, Authorize URL, Token URL, User Info URL, Scopes, **App Key** (header customizado), Provider. |

### 3. Auth Provider

| Arquivo | Descrição |
|--------|-----------|
| `authproviders/Ping_Federate_POC.authprovider-meta.xml` | Definição do Auth Provider tipo **Custom**, referenciando o plugin `PingFederateAuthProviderPlugin` e o Registration Handler `PingFederatePOCRegistrationHandler`. PKCE e `sendSecretInApis` configurados conforme necessário. |

### 4. Platform Cache

| Arquivo | Descrição |
|--------|-----------|
| `cachePartitions/PKCEPartition.cachePartition-meta.xml` | Partição de cache **PKCEPartition** (Organization + Session). Usada pelo plugin para armazenar o `code_verifier` entre `initiate` e `handleCallback`. É obrigatória no fluxo PKCE e precisa ter capacidade alocada em **Setup > Platform Cache**. |

---

## Pré-requisitos para funcionamento

1. **Usuários no Salesforce**  
   Usuário ativo com `FederationIdentifier` igual ao `sub` retornado pelo Ping Federate no `id_token`.

2. **SSO habilitado**  
   Em **Setup > Identity** verificar que Single Sign-On está configurado e que o campo `FederationIdentifier` está habilitado quando aplicável.

3. **Platform Cache**  
   A partição **PKCEPartition** deve existir e ter capacidade alocada em **Setup > Platform Cache**.

4. **Configuração do IdP**  
   No Ping Federate, a aplicação OAuth/Connected App deve estar configurada com as URLs corretas de callback (`https://<seu-org>.lightning.force.com/services/authcallback/Ping_Federate_POC`) e permitir o fluxo Authorization Code.

---

## URL de login SSO

```
https://<seu-dominio>.lightning.force.com/services/auth/sso/Ping_Federate_POC
```

Exemplo para org dev: `https://xxx.lightning.force.com/services/auth/sso/Ping_Federate_POC`

---

## Diagrama de dependências entre componentes

```
AuthProvider (Ping_Federate_POC)
    │
    ├── plugin: PingFederateAuthProviderPlugin
    │       │
    │       ├── config: PingFederateAuthConfig__mdt.Ping_Federate_POC
    │       └── cache: PKCEPartition (Platform Cache)
    │
    └── registrationHandler: PingFederatePOCRegistrationHandler
```
