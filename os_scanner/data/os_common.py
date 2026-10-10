"""
OutSystems common names for enumeration.

Sourced from:
- OutSystems Platform 11 default module names
- Common enterprise app naming conventions
- HAAK Cybersecurity 0-day research on OutSystems engagements
- OutSystems public documentation

Used by fingerprint, viewname_bypass, screen_enum, model_js, and exposure modules.
"""

# ─── Common OutSystems module / application names ─────────────────────────────

COMMON_MODULES = [
    # OutSystems platform built-ins
    "Common",
    "Users",
    "ECT_Provider",
    "EPA_TaskBox",
    "RichWidgets",
    "HttpRequestHandler",
    "EnhancedWebReferences",
    "Charts",
    "FileUploader",
    "Silk",
    "OutSystemsUI",
    "OutSystemsUIWeb",
    "GridAPI",
    "CefSharp",
    "ServiceCenter",
    "LifeTime",
    "LifeTimeCore",
    "LifeTimeAnalytics",
    "ServiceStudio",
    "OIDC_Provider",
    "OIDC_Admin",
    "IdP",
    "SSOProvider",
    "OutSystemsIdentity",
    "LDAPAuthentication",
    "SAMLAuthentication",
    "ADAuthenticationPlugin",

    # Common enterprise app patterns
    "Dashboard",
    "BackOffice",
    "Admin",
    "AdminPortal",
    "Portal",
    "API",
    "APIGateway",
    "Reports",
    "Settings",
    "Configuration",
    "Management",
    "UserManagement",
    "Authentication",
    "Notifications",
    "NotificationService",
    "Documents",
    "DocumentManagement",
    "Orders",
    "OrderManagement",
    "Payments",
    "PaymentGateway",
    "Customers",
    "CustomerPortal",
    "Products",
    "ProductCatalog",
    "Inventory",
    "Billing",
    "Invoicing",
    "Support",
    "Helpdesk",
    "HelpDesk",
    "Analytics",
    "Logging",
    "AuditLog",
    "Monitoring",
    "Integration",
    "Integrations",
    "Mobile",
    "MobileAPI",
    "Public",
    "External",
    "ExternalAPI",
    "Internal",
    "CaseManagement",
    "Cases",
    "Workflow",
    "TaskManager",
    "Tasks",
    "EmailService",
    "Email",
    "FileManager",
    "Files",
    "Search",
    "Catalog",

    # LATAM enterprise common names (from HAAK research)
    "Empleados",
    "Nomina",
    "Facturacion",
    "Clientes",
    "Proveedores",
    "Contabilidad",
    "RRHH",
    "Operaciones",
    "Logistica",
    "Rastreo",
    "Tracking",
    "Envios",
    "Recoleccion",
    "Rutas",
    "Almacen",
    "Inventario",
    "Cotizaciones",
    "Contratos",
]

# ─── Anonymous screen names for viewName auth bypass ─────────────────────────
#
# These are screens configured as "anonymous" (no role required) in OutSystems.
# Using one of these viewNames in a screenservice request can bypass role
# verification on other server actions in the same module.
#
# HAAK 0-day research: see ~/vault/06-research/outsystems-viewname-bypass.md

ANONYMOUS_SCREENS = [
    # Standard OutSystems login/auth screens
    "Login",
    "Common.Login",
    "UserResetPassword",
    "Common.UserResetPassword",
    "UserChangePassword",
    "Common.UserChangePassword",
    "Registration",
    "Common.Registration",
    "ForgotPassword",
    "Common.ForgotPassword",
    "InvalidPermissions",
    "Common.InvalidPermissions",
    "EmailConfirmation",
    "Common.EmailConfirmation",
    "ActivateAccount",
    "Common.ActivateAccount",
    "ConfirmEmail",
    "Common.ConfirmEmail",
    "ResetPassword",
    "Common.ResetPassword",
    "SetPassword",

    # Common public screens
    "Home",
    "Common.Home",
    "PublicHome",
    "Index",
    "Error",
    "Common.Error",
    "NotFound",
    "Common.NotFound",
    "Unauthorized",
    "Common.Unauthorized",
    "NoPermission",
    "Common.NoPermission",
    "SessionExpired",
    "Common.SessionExpired",
    "AccessDenied",
    "Maintenance",

    # Legal / informational
    "TermsOfService",
    "TermsAndConditions",
    "PrivacyPolicy",
    "ContactUs",
    "About",
    "Help",
    "FAQ",

    # API / integration callbacks
    "PublicAPI",
    "Webhook",
    "Callback",
    "OAuthCallback",
    "SAMLCallback",
    "SSOCallback",
    "OIDCCallback",
    "OIDCLogin",
    "OIDCLogout",
    "OIDCRedirect",

    # Common portal entry points
    "Landing",
    "Welcome",
    "Start",
    "Entry",
    "Guest",
]

# ─── Common server action names ───────────────────────────────────────────────
#
# Used by ViewNameBypassModule and ScreenEnumModule to enumerate
# server actions in a screenservice endpoint.

COMMON_ACTIONS = [
    # Lifecycle
    "OnInitialize",
    "OnReady",
    "OnParametersChanged",

    # User management
    "GetUser",
    "GetUsers",
    "GetUserById",
    "GetUserByEmail",
    "GetUserByUsername",
    "GetUserProfile",
    "GetProfile",
    "UpdateProfile",
    "UpdateUser",
    "CreateUser",
    "DeleteUser",
    "SearchUsers",
    "ListUsers",
    "GetAllUsers",
    "GetUserPermissions",
    "SetUserPermissions",
    "GetUserRoles",
    "SetUserRole",
    "DeactivateUser",
    "ActivateUser",
    "BlockUser",
    "UnblockUser",
    "GetUserDetails",
    "GetCurrentUser",
    "GetMe",
    "GetUserInfo",

    # Authentication
    "ValidateCode",
    "ResetPassword",
    "ChangePassword",
    "ForgotPassword",
    "SetPassword",
    "VerifyEmail",
    "SendVerificationCode",
    "ValidateToken",
    "RefreshToken",
    "Login",
    "Logout",
    "Register",
    "GetSession",
    "CheckSession",
    "ValidateSession",
    "IsAuthenticated",
    "GetAuthToken",
    "GenerateToken",
    "RevokeToken",

    # Data retrieval
    "GetAll",
    "GetById",
    "GetByName",
    "GetByCode",
    "GetList",
    "GetDetails",
    "Search",
    "Filter",
    "Export",
    "ExportExcel",
    "ExportCSV",
    "ExportPDF",
    "Import",
    "Download",
    "GetReport",
    "GetDashboard",
    "GetStats",
    "GetStatistics",
    "GetSummary",
    "GetCount",

    # Business entities
    "GetDocuments",
    "GetDocument",
    "GetOrders",
    "GetOrder",
    "GetOrderById",
    "GetPayments",
    "GetPayment",
    "GetTransactions",
    "GetTransaction",
    "GetInvoice",
    "GetInvoices",
    "GetCustomer",
    "GetCustomers",
    "GetProducts",
    "GetProduct",

    # CRUD
    "Create",
    "Update",
    "Delete",
    "Save",
    "Remove",
    "Edit",
    "Insert",
    "Upsert",
    "CreateRecord",
    "UpdateRecord",
    "DeleteRecord",
    "SaveRecord",
    "Submit",
    "Approve",
    "Reject",
    "Cancel",
    "Complete",

    # Admin / configuration
    "GetConfig",
    "GetConfiguration",
    "GetSettings",
    "UpdateSettings",
    "SaveSettings",
    "GetParameters",
    "GetSystemConfig",
    "GetEnvironmentConfig",
    "GetAppConfig",
    "GetFeatureFlags",

    # Logging / audit
    "GetLogs",
    "GetAuditLog",
    "GetErrors",
    "GetErrorLog",
    "GetMetrics",
    "GetEvents",

    # OIDC / OAuth / secrets
    "GetOIDCConfig",
    "GetProviderConfig",
    "GetClientSecret",
    "GetOAuthConfig",
    "GetAPIKeys",
    "GetIntegrationConfig",
    "GetCredentials",
]

# ─── Sensitive field name patterns ────────────────────────────────────────────
#
# Used by ModelJSModule to flag entity fields that may expose sensitive data.

SENSITIVE_FIELDS = [
    "password",
    "passwd",
    "pwd",
    "hash",
    "salt",
    "secret",
    "key",
    "token",
    "apikey",
    "api_key",
    "api_secret",
    "ssn",
    "social_security",
    "tax_id",
    "nif",
    "rfc",
    "curp",
    "credit_card",
    "card_number",
    "card_num",
    "cvv",
    "ccv",
    "cvc",
    "private_key",
    "privatekey",
    "client_secret",
    "clientsecret",
    "access_token",
    "accesstoken",
    "refresh_token",
    "refreshtoken",
    "id_token",
    "bearer",
    "session_id",
    "sessionid",
    "session_token",
    "auth_token",
    "pin",
    "otp",
    "mfa_code",
    "verification_code",
    "reset_code",
    "activation_code",
    "bank_account",
    "account_number",
    "routing_number",
    "iban",
    "swift",
    "clabe",
    "payment_token",
    "stripe_key",
    "paypal_secret",
]

# ─── Sensitive entity name patterns ───────────────────────────────────────────
#
# Entity names in model.js that warrant special attention.

SENSITIVE_ENTITIES = [
    "User",
    "Users",
    "Account",
    "Accounts",
    "Credential",
    "Credentials",
    "Session",
    "Sessions",
    "Token",
    "Tokens",
    "Password",
    "Passwords",
    "Secret",
    "Secrets",
    "Key",
    "Keys",
    "APIKey",
    "Certificate",
    "Certificates",
    "Payment",
    "Payments",
    "Transaction",
    "Transactions",
    "CreditCard",
    "BankAccount",
    "OIDC",
    "OIDCProvider",
    "OAuth",
    "OAuthProvider",
    "SSO",
    "SSOProvider",
    "Identity",
    "IdentityProvider",
    "AuditLog",
    "ErrorLog",
    "SecurityLog",
    "SecurityEvent",
    "Configuration",
    "SystemConfig",
    "Setting",
    "Settings",
    "Parameter",
    "Parameters",
    "SystemParameter",
    "EncryptionKey",
]

# ─── OutSystems platform fingerprint signatures ───────────────────────────────

OS_FINGERPRINTS = {
    "headers": [
        # (header_name, value_substring)
        ("X-Powered-By",  "ASP.NET"),
        ("Server",        "Microsoft-IIS"),
        ("X-AspNet-Version", ""),           # presence alone is a signal
        ("X-OutSystems-Version", ""),
    ],
    "cookies": [
        "osVisitor",
        "osVisit",
        "nr1",
        "nr1_csrf",
        "ASP.NET_SessionId",
        "outsystems",
        "nr1_userid",
        "nr2",
        "nr2_csrf",
        "OsAuthentication",
    ],
    "html_patterns": [
        r"outsystems",
        r"_osBlock",
        r"OssecLib",
        r"OutSystemsReactView",
        r"OutSystems\.Internal",
        r"outsystems-ui",
        r'data-block=["\']',
        r'data-input=["\']',
        r"os-internal-",
        r"ServiceCenter",
        r"LifeTime",
        r"os-ui-pattern",
        r"os-form-literal",
        r"os-loading-spinner",
        r"OutSystemsNativeMobile",
    ],
    "js_patterns": [
        r"OutSystemsPlatform",
        r"outsystems\.js",
        r"OSModules",
        r"OSController",
        r"screenservices/",
        r"moduleservices/",
        r"clientvariables/",
        r"OutSystemsReactView",
        r'"moduleVersion"',
        r"OutSystems\.Application",
    ],
    "url_patterns": [
        "/ServiceCenter",
        "/LifeTime",
        "/Users",
        "/screenservices/",
        "/moduleservices/",
        "/clientvariables/",
    ],
    # Path presence signals (check with HEAD/GET)
    "path_probes": [
        "/ServiceCenter",
        "/Users/Login.aspx",
        "/LifeTime",
    ],
}

# ─── REST API path patterns ───────────────────────────────────────────────────

REST_API_PATHS = [
    "/rest/",
    "/rest/v1/",
    "/rest/v2/",
    "/rest/v3/",
    "/api/",
    "/api/v1/",
    "/api/v2/",
    "/webservices/",
    "/soap/",
    "/_api/",
]

# ─── ServiceCenter / admin paths ──────────────────────────────────────────────

SERVICE_CENTER_PATHS = [
    "/ServiceCenter",
    "/ServiceCenter/Error_Log.aspx",
    "/ServiceCenter/ApplicationList.aspx",
    "/ServiceCenter/Monitoring.aspx",
    "/ServiceCenter/ModuleList.aspx",
    "/ServiceCenter/IntegrationLog.aspx",
    "/ServiceCenter/Timer_List.aspx",
    "/ServiceCenter/Deploy.aspx",
    "/ServiceCenter/SolutionList.aspx",
    "/ServiceCenter/Screen.aspx",
    "/ServiceCenter/Report_Screen.aspx",
    "/ServiceCenter/Environment.aspx",
    "/ServiceCenter/ServiceAPI",
    "/LifeTime",
    "/LifeTime/ApplicationList.aspx",
    "/LifeTime/EnvironmentList.aspx",
    "/Users",
    "/Users/Login.aspx",
    "/Users/EditMyProfile.aspx",
]

# ─── model.js path patterns to probe ─────────────────────────────────────────

MODEL_JS_PATHS = [
    "/{module}/model.js",
    "/{module}/scripts/model.js",
    "/{module}/scripts/{module}.model.js",
    "/scripts/{module}.model.js",
    "/{module}/_runtime/model.js",
    "/{module}/js/model.js",
]

# ─── OutSystems version fingerprint strings ──────────────────────────────────

VERSION_PATTERNS = [
    # (regex, group_index)
    (r"OutSystemsPlatform\.version\s*=\s*[\"']([0-9.]+)[\"']", 1),
    (r"Platform Server\s+([0-9]+\.[0-9]+\.[0-9.]+)", 1),
    (r"OutSystems\s+([0-9]+\.[0-9]+\.[0-9.]+)", 1),
    (r"moduleVersion\s*[\"']?\s*:\s*[\"']([0-9.]+)[\"']", 1),
    (r"X-OutSystems-Version:\s*([0-9.]+)", 1),
    (r"/\*[^*]*OutSystems[^*]*([0-9]+\.[0-9]+\.[0-9]+)", 1),
]

# ─── Default credentials to test ─────────────────────────────────────────────
#
# OutSystems default / well-known credentials.
# These are public knowledge and safe to include here.

DEFAULT_CREDENTIALS = [
    ("admin",   "admin"),
    ("admin",   "Admin1234"),
    ("admin",   "outsystems"),
    ("admin",   "OutSystems1"),
    ("admin",   ""),
    ("demo",    "demo"),
    ("test",    "test"),
    ("guest",   "guest"),
]

# ─── OIDC / OAuth configuration paths ────────────────────────────────────────

OIDC_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/OIDC_Provider/.well-known/openid-configuration",
    "/IdP/.well-known/openid-configuration",
    "/oauth/.well-known/openid-configuration",
    "/auth/.well-known/openid-configuration",
]

# ─── HTTP response codes that indicate "interesting" outcomes ────────────────

# These response codes during action enumeration deserve logging:
INTERESTING_STATUS_CODES = {200, 201, 206, 400, 403, 404, 409, 422, 500, 503}
# 401 = definitely rejected (auth working), skip
# 403 = forbidden but exists (useful for enumeration)
# 500 = server error — might reveal stack traces

# ─── Known OutSystems internal modules (usually shouldn't be on internet) ────

INTERNAL_MODULES = [
    "ECT_Provider",
    "EPA_TaskBox",
    "RichWidgets",
    "HttpRequestHandler",
    "EnhancedWebReferences",
    "ServiceCenter",
    "LifeTime",
    "LifeTimeCore",
    "LifeTimeAnalytics",
    "OIDC_Provider",
    "OIDC_Admin",
    "ADAuthenticationPlugin",
    "LDAPAuthentication",
    "SAMLAuthentication",
]
