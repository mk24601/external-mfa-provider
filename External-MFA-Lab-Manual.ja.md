# Microsoft Entra External MFA ボタン式ラボ構築・検証マニュアル

作成日・公式資料確認日: 2026-10-20

更新日: 2026-10-20

## この文書の目的

Azure App Service（Linux）上のPython / FlaskをExternal MFAプロバイダーとして使い、Microsoft Entra IDからの要求を受けて、承認ボタンを押すと署名付きIDトークンを返すラボを構築します。

本書は、サンプルコードを利用して自分の環境にラボを構築し、実際のサインインでExternal MFAを検証する人向けの手順です。Azureリソースの作成から、コードの設定、鍵生成、デプロイ、Entra側の設定、動作確認、後片付けまでを扱います。

概要は [README.md](./README.md) を参照してください。この文書では構築・検証の具体的な手順を説明します。

> **重要: 本物のMFAプロバイダーではありません。**
>
> ボタンを押すだけで、実際には行っていないOTPを模擬した成功応答を返します。個人検証用・破棄可能なラボ専用です。実業務のリソース、通常ユーザー、管理者、緊急アクセス用アカウントをこの方式で保護しないでください。

## 目次

1. [構成・前提条件・必要な権限](#prerequisites)
2. [自分の環境の値を記録する](#environment)
3. [Azure App Serviceを作成する](#azure-create)
4. [サンプルコードとローカル環境を準備する](#local-setup)
5. [Entraのアプリ登録を作成する](#app-registration)
6. [コードを自分の環境に合わせる](#code-settings)
7. [ラボ用の秘密鍵と証明書を生成する](#keys)
8. [ローカルで検証する](#local-tests)
9. [ZIPを作成してApp Serviceへデプロイする](#deployment)
10. [Azure上で起動・拒否動作を確認する](#azure-tests)
11. [EntraにExternal MFAプロバイダーを登録する](#provider-registration)
12. [テストユーザーにExternal MFAを登録する](#user-registration)
13. [MFA要求を用意する](#mfa-requirement)
14. [実際のサインインで確認する](#end-to-end)
15. [プロトコルの観察ポイント](#protocol)
16. [トラブルシューティング](#troubleshooting)
17. [ラボを停止・削除する](#cleanup)
18. [完了チェックリストと公式資料](#checklist)

<a id="prerequisites"></a>
## 1. 構成・前提条件・必要な権限

### 1.1 構成と検証範囲

```text
テストユーザーのブラウザー
    |
    | Entraにサインイン → MFA要求 → 外部MFAを選択
    v
Microsoft Entra ID
    |
    | ブラウザー経由のフォームPOST
    | id_token_hint / client_id / redirect_uri / nonce / state / claims
    v
Azure App Service Linux / Flask
    POST /authorize
      → リクエストとEntraのid_token_hintを検証
      → 検証済みリクエストを一時保存
      → 承認画面を表示
    POST /approve
      → 同じブラウザーから一度だけ承認
      → private.pemでRS256署名
      → HTMLフォームを自動POST
    |
    | id_token / state
    v
Microsoft Entra ID
      → プロバイダーの公開JWKSで署名とクレームを検証
      → ほかの要件も満たせばサインイン継続
```

公開するエンドポイント:

| メソッド | パス | 役割 |
|---|---|---|
| GET | `/` | 起動確認 |
| GET | `/health` | ヘルスチェック |
| GET | `/.well-known/openid-configuration` | Discovery |
| GET | `/.well-known/jwks` | 公開証明書・RSA公開鍵 |
| POST | `/authorize` | Entra要求の検証・承認画面の表示 |
| POST | `/approve` | 承認・署名・Entraへの応答 |

### 1.2 このラボの制限

- Azure Public Cloud / 単一Entraテナント専用です。政府機関向け・中国クラウドには、そのままでは対応しません。
- プロバイダー用アプリ登録とテストユーザーは、同じ検証用Entraテナントに作成します。
- 検証実績はApp ServiceのPython 3.14、ローカルのPython 3.13です。同じ構成で再現するなら、ローカルも利用可能なPython 3.14を推奨します。
- App Serviceは**1インスタンス**にします。承認情報はインスタンス内の一時ディレクトリにあるSQLiteで共有します。
- 同一インスタンスのGunicornワーカー間では共有できますが、複数インスタンスの分散保存ではありません。
- 一時データの消失・再起動・再デプロイをまたいだ承認継続は保証しません。失敗したらサインインをやり直します。
- 承認待ちは240秒、発行するIDトークンは120秒です。これはラボの実装値です。
- `acr=possessionorinherence`、`amr=["otp"]` に固定した模擬応答です。要求された `claims` がこれらを明示的に許可しない場合は拒否します。
- その他の追加必須クレームの要求にも、すべて対応する汎用OIDCプロバイダーではありません。
- 鍵をファイルとしてデプロイするのは今回のラボ用の簡略化です。

### 1.3 用意するもの

- 課金可能なAzureサブスクリプション。App Serviceプランの料金が発生します。
- 検証用Entraテナント。
- 通常業務や管理に使わないテストユーザー。最初の要素はパスワードでの検証を推奨します。
- テストユーザーだけを含むグループ。例: `External-MFA-Lab-Testers`。
- Windows / PowerShell / VS Code。
- Python、pip、Windowsの `curl.exe`。
- ZIPデプロイにAzure CLIを使用する場合は、最新のAzure CLI。本書のコマンドはローカルPowerShell用です。
- 条件付きアクセスでMFA要求を作る場合は、対象ユーザーに適切なMicrosoft Entra ID P1以上、または同機能を含むライセンス。

Microsoftの料金・ライセンス・ポータル画面・地域ごとのランタイム提供状況は変わります。使用前に末尾の公式資料と契約を確認してください。本書のライセンス記載は、特に条件付きアクセスを使う検証の前提です。

### 1.4 主な権限

| 操作 | 必要な権限の目安 |
|---|---|
| リソースグループ、App Serviceプラン、Webアプリの作成・設定・デプロイ | 対象AzureスコープのContributorなど |
| アプリ登録 | テナントのアプリ登録許可、または適切なアプリ管理権限 |
| External MFAの管理 | Authentication Policy Administrator以上 |
| External MFA登録画面での管理者同意 | Microsoftの手順ではPrivileged Role Administrator以上 |
| 一般ユーザーの認証方法登録 | Authentication Administratorなど。対象が管理者ならさらに強い権限が必要な場合あり |
| 条件付きアクセスポリシーの作成・変更 | Conditional Access Administrator以上 |

Azure RBACの権限とEntraディレクトリロールは別です。サブスクリプションのContributorでも、Entra設定を変更できるとは限りません。

**チェックポイント:** 検証専用アカウント・グループと、作業に必要な権限を用意できていること。

<a id="environment"></a>
## 2. 自分の環境の値を記録する

以降の値は**各自で作成・取得**します。サンプルコード内の既定値を流用せず、自分のホスト名、テナントID、App IDを設定し、自分の秘密鍵を生成してください。

| 記号 | 内容 | 記入例 |
|---|---|---|
| `SubscriptionId` | AzureサブスクリプションID | 自分のサブスクリプションのGUID |
| `ResourceGroup` | 専用リソースグループ | `rg-external-mfa-lab` |
| `PlanName` | Linux App Serviceプラン | `asp-external-mfa-lab` |
| `AppName` | Webアプリのリソース名 | `your-external-mfa-lab-unique` |
| `TenantId` | 検証用EntraテナントID | 自分のテナントのGUID |
| `ClientId` | 後で作るアプリのApplication (client) ID | 自分のアプリ登録のGUID |
| `HostName` | 作成したApp Serviceの実際の既定ドメイン | Azure Portalの概要からコピー |
| `BaseUri` | `https://` + `HostName` | 末尾の `/` は付けない |
| `TestUser` | 検証ユーザー | 自分のテストユーザー |
| `TestGroup` | 検証ユーザーだけを含むグループ | `External-MFA-Lab-Testers` |
| `TestResource` | MFA要求を確認するアクセス先アプリ | テストユーザーが利用できる検証用アプリ |

> **App Serviceのホスト名を推測しないでください。**
>
> 実際のホスト名にはランダムな識別子や地域名が含まれることがあります。必ずPortalの「概要」に表示された既定ドメインを使います。`AppName.azurewebsites.net` と決めつけないでください。

以降のコマンドで使う変数を、PowerShellに設定します。値は各自のものに置き換えます。

```powershell
$SubscriptionId = "<YOUR-SUBSCRIPTION-ID>"
$ResourceGroup = "rg-external-mfa-lab"
$PlanName = "asp-external-mfa-lab"
$AppName = "<YOUR-WEBAPP-RESOURCE-NAME>"
$TenantId = "<YOUR-TENANT-ID>"
```

`<...>` のまま実行しないでください。新しいターミナルでは変数を設定し直す必要があります。

### 2.1 テストユーザーとグループを新規作成する場合

既に検証専用のユーザーとグループがあれば、再作成は不要です。

1. Entra管理センターの**Entra ID → ユーザー → すべてのユーザー → 新しいユーザー → 新しいユーザーの作成**を開きます。
2. 検証用テナントのメンバーユーザーを作成します。ユーザー名・表示名はラボ用と分かるものにし、ディレクトリロールは割り当てません。
3. 初期パスワードは安全に保管し、本書や共有メモには記載しません。初回サインイン時の変更が必要なら、表示された手順に従います。
4. **Entra ID → グループ → すべてのグループ → 新しいグループ**を開きます。
5. 種類を**セキュリティ**、メンバーシップの種類を**割り当て済み（Assigned）**にし、例として `External-MFA-Lab-Testers` を作成します。
6. メンバーは上記テストユーザーだけにします。動的グループや大規模な既存グループは最初の検証には使用しません。
7. 条件付きアクセスを使う場合は、ライセンス管理の画面で対象ユーザーに適切なライセンスがあることを確認します。
8. 対象リソース側でアプリの割り当てや利用権が必要なら、テストユーザーへその権限を付与します。

ユーザー・グループの作成やライセンス割り当てにも、適切なユーザー／グループ／ライセンス管理権限が必要です。管理アカウントそのものをテストユーザーとして流用しません。

<a id="azure-create"></a>
## 3. Azure App Serviceを作成する

### 3.1 Azure PortalでWebアプリを作成

1. [Azure Portal](https://portal.azure.com/)にサインインします。
2. **リソースの作成 → Webアプリ**を開きます。
3. 次の項目を設定します。

| 項目 | 設定 |
|---|---|
| サブスクリプション | 自分の検証用サブスクリプション |
| リソースグループ | 検証専用のグループを新規作成 |
| 名前 | グローバルに使用可能なWebアプリ名 |
| 発行 | Code |
| ランタイムスタック | Python 3.14 |
| オペレーティングシステム | Linux |
| リージョン | Python 3.14が利用可能な希望リージョン。元の検証ではJapan West |
| Linuxプラン | 専用のApp Serviceプランを新規作成 |
| 価格プラン | 例: Basic B1。料金を確認して選択 |
| ネットワーク | Public accessを許可。外部からHTTPSでアクセス可能 |
| デプロイ | この段階で継続的デプロイを構成する必要なし |

4. **確認および作成 → 作成**を実行します。
5. 作成後、App Serviceの**概要**で既定ドメインをコピーします。
6. **スケールアウト**でインスタンス数を1にし、自動スケールアウトは構成しません。
7. **HTTPS Only**を有効にします。
8. App Serviceの**認証（Easy Auth）でサインイン必須にしない**でください。Discovery/JWKSやEntraからの要求を別のログイン画面で遮断しないためです。Entra要求の検証はFlask側で実施します。

表示位置はPortalの更新で変わる場合があります。Python 3.14が選択できない場合は、別リージョンやランタイム提供状況を確認し、別バージョンを使うならテストを再実行してください。

### 3.2 ホスト名とURLを設定

```powershell
$HostName = "<COPY-THE-ACTUAL-DEFAULT-HOSTNAME>"
$BaseUri = "https://$HostName"
$AuthorizationEndpoint = "$BaseUri/authorize"
$DiscoveryEndpoint = "$BaseUri/.well-known/openid-configuration"
```

ホスト名には `https://` や末尾の `/` を含めません。

### 3.3 Azure CLIを使用できることを確認

後のデプロイに使用します。Azure Cloud Shellではなく、コードを置いたローカルPCのPowerShellで実行してください。

```powershell
az version
az login --tenant $TenantId
az account set --subscription $SubscriptionId
az account show --query "{subscription:id, tenant:tenantId}" --output table
```

表示されたサブスクリプションとテナントを確認します。組織の制約で通常のログインが使えない場合は、認められたログイン手段を使用してください。

任意で実際のホスト名をCLIでも確認できます。

```powershell
az webapp show --resource-group $ResourceGroup --name $AppName --query defaultHostName --output tsv
```

**チェックポイント:** Webアプリ、プラン、リソースグループが作成され、実際のHTTPSホスト名が分かること。この時点の既定ページは、Flaskアプリの起動成功を意味しません。

<a id="local-setup"></a>
## 4. サンプルコードとローカル環境を準備する

### 4.1 使用するソース

GitHubから取得した場合は、リポジトリをローカルに展開し、その中の `external-mfa-provider` を作業ディレクトリにします。使用するソースは以下の5ファイルです。

- [app.py](./external-mfa-provider/app.py)
- [requirements.txt](./external-mfa-provider/requirements.txt)
- [authorize.html](./external-mfa-provider/templates/authorize.html)
- [form_post.html](./external-mfa-provider/templates/form_post.html)
- [test_app.py](./external-mfa-provider/test_app.py)

秘密鍵・証明書は、第7章の手順で自分の環境に生成します。

```text
取得したフォルダー/
├── README.md
├── External-MFA-Lab-Manual.ja.md
└── external-mfa-provider/
    ├── app.py
    ├── requirements.txt
    ├── test_app.py
    └── templates/
        ├── authorize.html
        └── form_post.html
```

**取得したソース一式と、AzureへデプロイするZIPは別です。** デプロイ用ZIPには、自分で生成した鍵ペアを含めます。

GitHubの「Download ZIP」は、上記全体をリポジトリ名のフォルダーで包んだソースアーカイブです。秘密鍵も含まないため、**ダウンロードしたZIPをそのままApp Serviceへデプロイしないでください。** 各自で設定変更・鍵生成・テストを行い、第9章でデプロイZIPを作成します。

### 4.2 Pythonと依存関係

PowerShellで、自分の配置先に移動します。

```powershell
Set-Location 'C:\Lab\external-mfa-provider'
python --version
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r .\requirements.txt
```

本書では仮想環境の有効化に依存せず、実行するPythonを明示します。PowerShellの実行ポリシーを変更する必要はありません。

依存関係:

```text
Flask
gunicorn
PyJWT
cryptography
requests
```

- Windowsローカルでは `python app.py` に相当するFlask開発サーバーを使います。
- LinuxのApp ServiceではGunicornを使います。WindowsでGunicornを起動する必要はありません。
- サンプルコードは依存バージョンを固定していません。再現時にはPythonとライブラリのバージョンも記録してください。

```powershell
.\.venv\Scripts\python.exe -m pip freeze
```

<a id="app-registration"></a>
## 5. Entraのアプリ登録を作成する

### 5.1 新しいアプリ登録

1. [Microsoft Entra管理センター](https://entra.microsoft.com/)を開きます。
2. 作業対象ディレクトリが検証用テナントであることを確認します。
3. **Entra ID → アプリの登録 → 新規登録**を開きます。
4. 以下を設定し、登録します。

| 項目 | 設定 |
|---|---|
| 名前 | `External MFA Lab` など |
| サポートされるアカウントの種類 | この組織ディレクトリのみ。シングルテナント |
| リダイレクトURIのプラットフォーム | Web |
| リダイレクトURI | `BaseUri` + `/authorize` |

入力例は `https://<自分の実際のホスト名>/authorize` です。Portalには `<...>` を含まない実際のURLを入力します。

5. **概要**から以下を控えます。
   - Application (client) ID
   - Directory (tenant) ID

```powershell
$ClientId = "<YOUR-APPLICATION-CLIENT-ID>"
```

Application Object ID、Enterprise applicationのObject ID、AzureリソースIDではありません。

### 5.2 APIのアクセス許可と同意

1. アプリ登録の**APIのアクセス許可 → アクセス許可の追加**。
2. **Microsoft Graph → 委任されたアクセス許可**。
3. `openid` と `profile` を追加します。
4. **テナントに管理者の同意を与えます**を実行します。
5. 対象テナントに対してGrantedになっていることを確認します。

`User.Read` が既定で存在しても、このアプリのコードはMicrosoft Graphを呼びません。追加は不要です。既存の権限を消す場合は、このラボ専用のアプリであることを確認します。

### 5.3 設定しないもの

- クライアントシークレットは作成しません。
- 独自スコープを公開しません。
- `cert.pem` をアプリ登録の証明書資格情報としてアップロードする必要はありません。
- 「暗黙的な許可およびハイブリッドフロー」のチェックボックスは、本手順のために変更していません。独立した一般OIDCクライアントの設定と混同しないでください。

### 5.4 2種類のURLを混同しない

| 用途 | 設定するURL |
|---|---|
| アプリ登録のWebリダイレクトURI | **自分のプロバイダーの `/authorize`** |
| Entraがプロバイダーに渡す応答先 `redirect_uri` | **`https://login.microsoftonline.com/common/federation/externalauthprovider`** |

後者をアプリ登録の `/authorize` の代わりに入力しないでください。このラボはGlobal Azureの応答先をコードで固定許可しています。

**チェックポイント:** Webの `/authorize` URL、Application (client) ID、テナントID、`openid` / `profile` の管理者同意を確認できること。

<a id="code-settings"></a>
## 6. コードを自分の環境に合わせる

現行の [app.py](./external-mfa-provider/app.py) では、issuerはコード内の定数、テナントIDとClient IDは環境変数とコード内の既定値で設定します。**自分のコピー**で以下の3か所を変更します。

設定値がプレースホルダーでも、別の環境の既定値でも、以下の手順で自分の値に置き換えます。現行コードでは3項目すべてを環境変数だけで設定することはできません。

### 6.1 issuer

既存の複数行の `ISSUER = (...)` を、自分の実際のApp Service URLに置き換えます。

```python
ISSUER = "https://YOUR-ACTUAL-APP-SERVICE-HOSTNAME"
```

- 実際のホスト名を使います。
- 末尾の `/` は付けません。
- `http://localhost:8000` にはしません。ローカルのDiscoveryもAzure用issuerを返す設計です。
- **現行コードは `ISSUER` 環境変数を読みません。** App Serviceの設定に同名の変数を追加するだけでは変更されません。

### 6.2 テナントIDとClient ID

既存の設定ブロックを、自分のGUIDに置き換えます。

```python
app.config["ENTRA_TENANT_ID"] = os.environ.get(
    "ENTRA_TENANT_ID", "YOUR-TENANT-GUID"
)
app.config["ENTRA_CLIENT_ID"] = os.environ.get(
    "ENTRA_CLIENT_ID", "YOUR-APPLICATION-CLIENT-GUID"
)
```

`YOUR-...` は説明用の置き換え箇所です。必ず実際のGUIDにします。

この2項目は環境変数で上書きできます。アプリ登録のObject IDは使用しません。

ローカルのPowerShellにも値を設定しておきます。

```powershell
$env:ENTRA_TENANT_ID = $TenantId
$env:ENTRA_CLIENT_ID = $ClientId
```

コード内の既定値も置き換えておくことで、環境変数を設定し忘れて別の環境を参照する事故を防ぎます。

### 6.3 そのままにする値

- `ENTRA_REDIRECT_URI`: Global Azureの固定応答先。
- `LAB_ACR`: `possessionorinherence`。
- `LAB_AMR`: `otp`。
- `PRIVATE_KEY_PATH`: `private.pem`。
- `CERT_PATH`: `cert.pem`。

**チェックポイント:** ホスト名・テナントID・App IDがすべて自分の環境の値になっていること。

<a id="keys"></a>
## 7. ラボ用の秘密鍵と証明書を生成する

### 7.1 目的とファイル名

| ファイル | 用途 | 取り扱い |
|---|---|---|
| `private.pem` | 返却IDトークンのRS256署名 | 秘密として管理 |
| `cert.pem` | 対応するRSA公開鍵とX.509証明書 | JWKSとして公開される |

`private.pemm` / `cert.pemm` のような別名では起動しません。Windowsエクスプローラーでは拡張子を表示して確認してください。

次のコマンドはPythonのcryptographyを使います。OpenSSLの別途インストールは不要です。RSA 2048ビット、365日有効の自己署名証明書を生成します。

この証明書はJWKSの公開鍵コンテナーです。App ServiceのHTTPSサーバー証明書とは別物であり、App ServiceのTLS設定にアップロードしません。

### 7.2 生成コマンド

プロジェクトディレクトリで実行します。既存ファイルがある場合は上書きせず停止します。

```powershell
@'
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

private_path = Path("private.pem")
cert_path = Path("cert.pem")
if private_path.exists() or cert_path.exists():
    raise SystemExit("Key or certificate already exists. Do not overwrite an active lab key.")

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "External MFA Lab Signing")
])
now = datetime.now(timezone.utc)
certificate = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - timedelta(minutes=5))
    .not_valid_after(now + timedelta(days=365))
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .sign(key, hashes.SHA256())
)
with private_path.open("xb") as output:
    output.write(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
with cert_path.open("xb") as output:
    output.write(certificate.public_bytes(serialization.Encoding.PEM))
print("Created private.pem and cert.pem. Keep the private key secret.")
'@ | .\.venv\Scripts\python.exe -
```

本書の鍵はパスフレーズなしです。これもラボ用の簡略化です。

> 元のデプロイZIPや他人の秘密鍵を再利用しないでください。また、一度Entraで使い始めた鍵を気軽に再生成しないでください。Entraのメタデータ／公開鍵キャッシュにより、新旧鍵の不一致が起こり得ます。

**チェックポイント:** 各自の新しい `private.pem` と `cert.pem` が存在し、秘密鍵を画面やチャットに出していないこと。

<a id="local-tests"></a>
## 8. ローカルで検証する

### 8.1 自動テスト

```powershell
.\.venv\Scripts\python.exe -B -m unittest test_app -v
```

本書作成時点のコードでは、最後に次が出ます。

```text
Ran 25 tests ...

OK
```

途中の `WARNING` / `ERROR` には、意図的な不正要求や通信障害の模擬によるものがあります。各テストの `ok` と末尾の `OK` を確認します。実際の例外や `FAILED` は無視しません。

テスト対象:

- 期限切れの正しい署名付きヒントの受け入れ。
- 不正な署名・issuer・audience・テナント・必須クレームの拒否。
- 固定のラボ用 `acr` / `amr` を許可しない要求の拒否。
- 承認トランザクションのブラウザーひも付け、期限、同時実行、二重使用防止。
- 返却トークンを公開JWKSで検証できること。
- `sub` / `nonce` / `state` と返却先の正しい引き継ぎ。
- 鍵と証明書の一致、不正なフォーム入力、明示的な障害通知。

**注意:** 自動テストでは、Entraの検証鍵取得をテスト用に差し替えます。Entraとの実際の往復成功を意味しません。アプリ本体に検証スキップ用のモードはありません。

### 8.2 Flaskを起動

```powershell
.\.venv\Scripts\python.exe .\app.py
```

起動したターミナルは開いたままにします。停止は `Ctrl+C` です。設定や鍵を変更したら再起動します。

### 8.3 4つのURLを確認

| URL | 期待値 |
|---|---|
| `http://localhost:8000/` | `Mini External MFA Provider is running!` |
| `http://localhost:8000/health` | `status` が `ok` |
| `http://localhost:8000/.well-known/openid-configuration` | 自分のAzureのissuerとURL、`id_token` / `form_post` / `RS256` |
| `http://localhost:8000/.well-known/jwks` | RSA鍵が1つ。`kid` / `n` / `e` / `x5c` がある |

ローカルのDiscoveryでもAzureのURLが返るのは意図どおりです。JWKSをローカルで確認する場合は、上表のlocalhost URLを明示して開きます。

### 8.4 偽トークンを拒否することを確認

別のPowerShellを開き、`ClientId` を設定して実行します。

```powershell
$ClientId = "<YOUR-APPLICATION-CLIENT-ID>"
$LocalBaseUri = "http://localhost:8000"

curl.exe -i -X POST "$LocalBaseUri/authorize" `
  --data-urlencode "scope=openid" `
  --data-urlencode "response_type=id_token" `
  --data-urlencode "response_mode=form_post" `
  --data-urlencode "client_id=$ClientId" `
  --data-urlencode "redirect_uri=https://login.microsoftonline.com/common/federation/externalauthprovider" `
  --data-urlencode "nonce=lab-nonce" `
  --data-urlencode "state=lab-state" `
  --data-urlencode "id_token_hint=not-a-real-token"
```

期待値:

```text
HTTP/1.1 400 BAD REQUEST
```

```json
{
  "error": "invalid_id_token_hint",
  "error_description": "id_token_hint failed signature or claim validation."
}
```

400はこのテストでは成功です。形式不正なヒントはEntraへの通信前に拒否されます。正しいEntraヒントを検証したことにはなりません。

ブラウザーで直接 `/authorize` を開くとGETになるため、405になります。これも正常です。

**チェックポイント:** 自動テストの `OK`、4つのGET、偽トークンに対する400を確認してからAzureへ進みます。

<a id="deployment"></a>
## 9. ZIPを作成してApp Serviceへデプロイする

### 9.1 App Serviceの設定

Azure PortalのApp Serviceで、**設定 → 環境変数**などの画面から次を追加し、適用します。

| 名前 | 値 |
|---|---|
| `SCM_DO_BUILD_DURING_DEPLOYMENT` | `true` |
| `ENTRA_TENANT_ID` | 自分のテナントGUID |
| `ENTRA_CLIENT_ID` | 自分のアプリ登録のClient ID |

CLIでも設定できます。第2・3・5章の変数が入ったPowerShellを使います。

```powershell
az webapp config appsettings set `
  --resource-group $ResourceGroup `
  --name $AppName `
  --settings "SCM_DO_BUILD_DURING_DEPLOYMENT=true" "ENTRA_TENANT_ID=$TenantId" "ENTRA_CLIENT_ID=$ClientId"
```

ZIPソースをOryxでビルドする方式です。別方式の `WEBSITE_RUN_FROM_PACKAGE` と混在させないでください。既存設定がある環境では、それがこのラボに必要なものか確認します。

### 9.2 起動コマンド

App Serviceの**構成 / スタック設定 / 全般設定**などの画面にあるStartup Commandへ、次を設定します。

```text
gunicorn --bind 0.0.0.0:8000 --workers 1 --timeout 120 --access-logfile - --error-logfile - app:app
```

CLIで設定する場合:

```powershell
az webapp config set `
  --resource-group $ResourceGroup `
  --name $AppName `
  --startup-file "gunicorn --bind 0.0.0.0:8000 --workers 1 --timeout 120 --access-logfile - --error-logfile - app:app"
```

`app:app` は「`app.py` 内のFlaskオブジェクト `app`」を指します。Azure上では `python app.py` の開発サーバーを起動しません。

### 9.3 ZIPの作成

プロジェクトディレクトリで実行します。

```powershell
$DeploymentZip = Join-Path (Split-Path -Parent (Get-Location).Path) "external-mfa-provider-deploy.zip"
Compress-Archive `
  -Path .\app.py, .\requirements.txt, .\private.pem, .\cert.pem, .\templates `
  -DestinationPath $DeploymentZip `
  -Force
```

このコマンドは、指定したデプロイ用ZIPを上書きします。同じ名前の別の成果物がないことを確認してください。

ZIPの直下を次の構造にします。

```text
app.py
requirements.txt
private.pem
cert.pem
templates/
    authorize.html
    form_post.html
```

含めないもの:

- 外側の `external-mfa-provider` フォルダー。
- `.venv`、`__pycache__`、テスト用一時データ。
- SQLiteデータベース。
- 自動テストや本マニュアル。デプロイに必須ではありません。

ZIPは秘密鍵を含むため、安全な場所に保管し、自分のApp Serviceへのデプロイに使用してください。

### 9.4 ZIPをデプロイ

本書では、Linuxでも再現しやすいAzure CLI方式を基本とします。

```powershell
az webapp deploy `
  --resource-group $ResourceGroup `
  --name $AppName `
  --src-path $DeploymentZip `
  --type zip
```

コマンドの終了結果とApp Serviceのデプロイログを確認します。サーバー側で依存パッケージがインストールされ、アプリが起動するまで待ちます。

**Portal経由について:** 元の検証ではPortalからZIPをアップロードしましたが、表示されるUIは環境・時期で異なります。公式資料では、従来のKudu **Tools → Zip Push Deploy** UIはLinuxでは使用できないと記載されています。Linuxでその画面がない／動かない場合は、上記CLI方式を使ってください。

最新のAzure CLIは `az webapp deploy` でEntra認証を利用できます。ZIPデプロイのためだけにBasic認証を有効化することを、本書の標準手順にはしていません。

### 9.5 ログ

Portalの**監視 → ログストリーム**を開きます。必要に応じてApp Serviceログのアプリケーションログを有効にしてください。

デプロイ失敗時はDeployment Centerのログも確認します。ログ確認のために秘密鍵の内容を出力する必要はありません。

**チェックポイント:** デプロイの成功と、Gunicornの起動を確認できること。

<a id="azure-tests"></a>
## 10. Azure上で起動・拒否動作を確認する

新しいPowerShellでは、自分の値を設定し直します。

```powershell
$BaseUri = "https://<YOUR-ACTUAL-APP-SERVICE-HOSTNAME>"
$ClientId = "<YOUR-APPLICATION-CLIENT-ID>"
```

### 10.1 4つのGET

ブラウザーで `BaseUri` に以下のパスを付けて開きます。PowerShellでは次を使えます。

```powershell
Invoke-RestMethod "$BaseUri/"
Invoke-RestMethod "$BaseUri/health"
Invoke-RestMethod "$BaseUri/.well-known/openid-configuration" | ConvertTo-Json -Depth 5
Invoke-RestMethod "$BaseUri/.well-known/jwks" | ConvertTo-Json -Depth 5
```

| 確認 | 期待値 |
|---|---|
| ルート | 起動メッセージ |
| ヘルス | `status=ok` |
| Discovery | 自分のHTTPS issuer、`/authorize`、JWKS URL |
| JWKS | ローカルと同じ `kid`、公開証明書 |

起動できない場合は先へ進まず、鍵のファイル名、ZIP構造、依存関係、Startup Command、ログを確認します。

### 10.2 偽のヒントを送る

```powershell
curl.exe -i -X POST "$BaseUri/authorize" `
  --data-urlencode "scope=openid" `
  --data-urlencode "response_type=id_token" `
  --data-urlencode "response_mode=form_post" `
  --data-urlencode "client_id=$ClientId" `
  --data-urlencode "redirect_uri=https://login.microsoftonline.com/common/federation/externalauthprovider" `
  --data-urlencode "nonce=lab-nonce" `
  --data-urlencode "state=lab-state" `
  --data-urlencode "id_token_hint=not-a-real-token"
```

期待値は**400**、`error=invalid_id_token_hint` です。502や500を成功扱いしないでください。

### 10.3 存在しない承認を送る

```powershell
curl.exe -i -X POST "$BaseUri/approve" `
  --data-urlencode "transaction_id=not-a-real-transaction"
```

期待値:

```text
HTTP/1.1 400 BAD REQUEST
```

```json
{
  "error": "invalid_transaction",
  "error_description": "Missing or invalid approval transaction."
}
```

404なら `/approve` のない古いコードが動いている可能性があります。

> この章は起動と拒否動作のテストです。成功パスのテンプレート表示、SQLiteへの保存、Entraへのトークン返却の成功は、これだけでは確認できません。

**チェックポイント:** 4つのGET、2つの意図した400応答を確認できること。

<a id="provider-registration"></a>
## 11. EntraにExternal MFAプロバイダーを登録する

### 11.1 プロバイダーを追加

1. **Entra ID → 認証方法 → 外部MFAの追加（Add external MFA）**を開きます。
2. 以下を設定します。

| 項目 | 値 |
|---|---|
| Name | 例: `External MFA Lab - Button Only` |
| Client ID | 自分の `ClientId` |
| Discovery Endpoint | 自分の `BaseUri` + `/.well-known/openid-configuration` |
| App ID | 自分の `ClientId` |

**このラボではClient IDとApp IDを同じGUIDにする設計です。** 一般の商用プロバイダーで、必ず同一になるという意味ではありません。

Nameはユーザーの認証方法選択画面に表示され、作成後は変更できません。ラボだと明確な名前にします。

### 11.2 同意

**Request admin consent** が必要な場合は実施し、**Admin consent granted** を確認します。事前のアプリ登録での同意だけで、この画面の状態まで確認したことにはしません。

権限が不足する場合は、必要なロールを持つ管理者に実施してもらいます。未同意のまま動作するとは考えないでください。

### 11.3 対象範囲と有効化

1. Includeの既定値に **All users** があれば削除します。
2. テストユーザー／テストグループだけを追加します。
3. 管理者・緊急アクセス用アカウントが対象でないことを確認します。
4. 対象を限定した状態でEnableをOnにして保存します。

対象をその場で限定できない場合は、一旦Offで保存してから対象を設定し、その後に有効化します。

**All usersのまま有効化しないでください。** 認証方法を有効にすると、対象ユーザーが実際のMFA要求で選べる可能性があります。

**チェックポイント:** 有効、同意済み、対象はテストユーザーのみ、Discovery URLは自分の完全なURLであること。

<a id="user-registration"></a>
## 12. テストユーザーにExternal MFAを登録する

元の検証では、プロバイダーを有効にした直後は選択肢に表示されず、ユーザーへの登録を確認した後に表示されました。単に「しばらく待つ」だけで済ませず、この項目を確認します。

登録の要否・表示はポリシーやユーザー状態にも依存します。本書では再現性を優先し、**管理者による明示的な登録**を行います。

### 12.1 管理者による登録（基本手順）

1. **Entra ID → ユーザー → すべてのユーザー**。
2. テストユーザーを開きます。
3. **認証方法（Authentication methods）**。
4. **＋認証方法の追加（Add authentication method）**。
5. **External authentication method**。
6. 今回のラボプロバイダーを選択して保存します。
7. **Usable authentication methods** に表示されたことを確認します。

操作は、テスト中のサインイン画面とは別の管理者用ブラウザーで行います。

### 12.2 ユーザーによる登録（代替手順）

現行のMicrosoft手順では、[Security info](https://mysignins.microsoft.com/security-info) の **Add sign-in method → External Auth methods**、または登録ウィザードから登録できます。

この経路では外部プロバイダーでの確認が必要です。登録画面へ進むために既存の認証方法を要求される場合もあるため、最初のラボでは12.1を基本にします。

**チェックポイント:** テスト対象ユーザーの利用可能な認証方法に、作成したExternal MFAがあること。

<a id="mfa-requirement"></a>
## 13. MFA要求を用意する

**External MFAを有効化・登録する操作と、MFAを要求する操作は別です。**

### 13.1 既にMFAが要求される場合

元の検証では既存のMFA要求を利用しました。同じ条件を満たす場合は新しいポリシーを追加しません。

- テストユーザーでMFAが要求されるアクセス先を使います。
- 管理者ではなく、通常の検証ユーザーで試します。
- 他の認証強度・デバイス条件・リスク条件なども含む場合、ボタン式External MFAだけでは満たせないことがあります。

### 13.2 MFA要求がない場合だけ、専用の条件付きアクセスを作る

本番テナントの既存ポリシーを緩めるのではなく、隔離した検証環境で実施します。

1. **Entra ID → 条件付きアクセス → ポリシー → 新しいポリシー**。
2. 名前を `LAB - External MFA - Test users only` などにします。
3. **ユーザー**はテストグループだけを含めます。All usersにはしません。
4. 管理者・緊急アクセス用アカウントは対象外であることを確認します。
5. **ターゲットリソース**はテストユーザーが利用できる1つの検証用リソースに限定します。
6. **アクセス制御 → 許可 → アクセス権の付与**。
7. **Require multifactor authentication（多要素認証を要求する）**を選択します。
8. 最初は**レポート専用**で保存し、対象をWhat Ifやサインインログで確認します。
9. 対象・除外を確認した後、テスト用ポリシーだけを**On**にします。

レポート専用ではMFAを強制しません。実際のMFA画面を出す試験ではOnが必要です。

> **Require authentication strengthではなく、Require multifactor authenticationを使います。**
>
> Microsoftの現行資料ではExternal MFAは認証強度と互換性がありません。組み込みの「Multifactor authentication strength」も、ここでいう従来のRequire multifactor authenticationとは別です。

このポリシーのターゲットは、実際にアクセスするリソースです。External MFA連携用アプリ登録を、テスト用のアクセス先と混同しないでください。

既存の検証用アプリがなければ、まずテストユーザーが利用できるEntra連携リソースとそのサインインURLを管理者と決めます。利用可能なMicrosoft 365サービスなどを使う場合も、必要なライセンスとアクセス権を確認してください。今回のFlaskの公開トップページを開くだけでは、Entraサインインや条件付きアクセスは発生しません。

セキュリティの既定値や既存の強いポリシーを安易に無効化して試験を通さないでください。共存しない設定がある場合は、専用テナントの構成を管理者と確認します。

**チェックポイント:** テストユーザーが対象リソースへのアクセス時にMFAを要求され、External MFAでは満たせない認証強度ポリシーを試験条件にしていないこと。

<a id="end-to-end"></a>
## 14. 実際のサインインで確認する

### 14.1 事前準備

- App Serviceのログストリームを開きます。
- テストユーザーに適用するポリシーと登録状態を確認します。
- InPrivate / シークレットウィンドウを開きます。設定前から開いている認証画面は使い回しません。
- 最初の要素としてパスワードを使う流れを推奨します。既にMFAが満たされるパスワードレス認証などでは追加の選択画面が出ない場合があります。

### 14.2 選択画面まで進む

1. MFAを要求するテスト対象リソースへアクセスします。
2. テストユーザーでサインインします。
3. Authenticatorが先に表示された場合は、**別の方法でサインイン**などを選択します。
4. 今回のExternal MFAの表示名を選択します。

System-preferred authenticationにより他の方法が先に表示されても、External MFAが使用不可とは限りません。既存のAuthenticatorを削除して切り替える必要はありません。

期待する表示例:

```text
Verify your identity
    Approve a request on my Microsoft Authenticator app
    Approve with External MFA Lab
    Use a verification code
```

表示文言は言語・登録名・ポータル更新で異なります。

### 14.3 承認画面

App Serviceへ移動し、次が表示されることを確認します。

- `External MFA Lab`。
- 署名・issuer・audience・テナントの検証成功の説明。
- 検証済み `tid` / `sub` / `oid`。
- `client_id` / `redirect_uri` / `nonce` / `state`。
- Entraが要求する `claims` のJSON。
- 実際のOTPは行わないという注意。
- **Approve MFA (LAB ONLY)** ボタン。

この画面が表示されたら、実際のEntraヒントの検証と承認用情報の保存まで進んだことを確認できます。

### 14.4 承認と返却

1. 承認画面を開いてから**4分以内**にボタンを押します。
2. `/approve` が署名付きIDトークンを作成します。
3. ブラウザーがEntraの固定応答先へ `id_token` と、存在する場合の `state` を自動POSTします。
4. Entraの検証に成功し、ほかの条件も満たすと元のリソースへ進みます。

返却ページは自動遷移するため、一瞬しか見えない場合があります。JavaScriptが動かない場合にはContinueボタンがあります。

同じ承認は再使用できません。戻るボタンで再度押したり、4分を超えたり、承認途中で再デプロイした場合は最初からサインインをやり直します。

### 14.5 Entra側のログ

**Entra ID → 監視と正常性 → サインインログ**で、テストユーザー・時刻・対象リソースに対応する対話型サインインを確認します。

- Status、エラーコード、Correlation ID。
- Authentication Details / 認証の詳細。
- Conditional Access / 条件付きアクセスの適用結果。
- 今回の新しい要求でMFAが満たされたのか、以前のセッション／クレームで満たされていないか。

ログの表示名や項目は変わることがあります。画面遷移、App ServiceのPOST、Entraログの3つを対応付けます。

**成功条件:** External MFAを選び、自分の承認画面でボタンを押し、Entraへ戻ってテスト対象リソースへのサインインを完了できること。GETの成功や拒否テストだけで完了扱いしません。

<a id="protocol"></a>
## 15. プロトコルの観察ポイント

### 15.1 ブラウザー開発者ツール

検証ユーザーのブラウザーで開発者ツールのNetworkを開き、必要ならPreserve logを有効にしてからサインインをやり直します。

| 通信 | 観察するもの |
|---|---|
| プロバイダーへの `POST /authorize` | フォームの `id_token_hint`、`client_id`、`redirect_uri`、`nonce`、`state`、`claims` |
| プロバイダーへの `POST /approve` | ランダムな `transaction_id`。本人情報や返却先をブラウザーから再指定しない設計 |
| EntraへのフォームPOST | `id_token`、存在する場合の `state` |

EntraサーバーによるDiscovery/JWKS取得や、FlaskサーバーによるEntra公開鍵取得は、ブラウザーのNetworkに必ず見えるものではありません。

> JWT・Cookie・状態値・HARファイルには個人情報や認証関連情報が含まれます。チャットや公開チケットへ全文を貼らず、外部JWTデコーダーにも送信しないでください。観察はローカルで行い、証跡は必要な部分だけマスクします。

### 15.2 Discovery

| フィールド | このラボの意味 |
|---|---|
| `issuer` | プロバイダーの固定HTTPS識別子。返却JWTの `iss` と文字単位で一致 |
| `authorization_endpoint` | 自分の `/authorize` |
| `jwks_uri` | 自分の公開鍵配信URL |
| `response_types_supported` | `["id_token"]`。認可コード交換ではない |
| `response_modes_supported` | `["form_post"]`。HTMLフォームのPOSTで返す |
| `id_token_signing_alg_values_supported` | `["RS256"]` |
| `scopes_supported` | `["openid"]` |
| `subject_types_supported` | `["public"]`。秘密鍵公開を意味しない |

FlaskのJSON応答にはContent-Lengthも付与されます。MicrosoftはDiscovery応答の有効なContent-Lengthを要求しています。

### 15.3 JWKS

| フィールド | 内容 |
|---|---|
| `kty` | `RSA` |
| `use` | `sig`。署名用途 |
| `kid` | 証明書SHA-256フィンガープリントのパディングなしBase64url。返却JWTヘッダーと一致 |
| `alg` | `RS256` |
| `n` | RSA公開鍵のmodulus。パディングなしBase64url |
| `e` | RSA公開鍵のexponent。通常の65537は `AQAB` |
| `x5c` | 証明書DERを**通常のBase64**にした配列。PEMのヘッダーは含めない |

MicrosoftのExternal MFAでは `x5c` が必要です。`n` / `e` と同じ公開鍵を表します。JWKに秘密鍵の成分は含めません。

### 15.4 `id_token_hint` の期限

MicrosoftのExternal MFA仕様では、ヒントは期限切れ状態で発行されると説明されています。

この実装は**ヒントだけ** `exp` の期限判定を無効にし、`exp` 自体の存在・整数形式は確認します。署名、RS256、issuer、audience、テナント、必須クレーム、`iat`、存在する場合の `nbf` などの検証は維持します。

返却IDトークンの有効期限まで無視してよいという意味ではありません。また、このヒントを自分のサービスへの汎用ログイン資格情報として使いません。

### 15.5 返却するIDトークン

説明用の例です。実際の値は要求と時刻で変わります。

```json
{
  "iss": "https://YOUR-ACTUAL-APP-SERVICE-HOSTNAME",
  "aud": "YOUR-APPLICATION-CLIENT-GUID",
  "sub": "VERIFIED-SUB-FROM-ID-TOKEN-HINT",
  "iat": 1700000000,
  "exp": 1700000120,
  "nonce": "SAME-NONCE-AS-AUTHORIZATION-REQUEST",
  "acr": "possessionorinherence",
  "amr": ["otp"]
}
```

- `sub` は検証済みヒントの `sub` と同じ。`oid` やメールアドレスへ置き換えません。
- `aud` はこのラボで検証した要求のClient ID。任意のMicrosoftアプリのIDではありません。
- `nonce` はヒント内のnonceではなく、**今回の認可リクエストのnonce**を引き継ぎます。未指定なら作りません。
- `state` はJWTに入れず、返却フォームにそのまま入れます。未指定ならフォームにも入れません。
- `acr` は文字列を1つ、`amr` は方式を1つだけ含む配列です。
- `acr` / `amr` は本物の要素の実施を保証するものではなく、このラボでは模擬申告です。

`nonce` と `state` は今回の要求に結び付けて保持・返却します。プロバイダー側ではEntraが元々期待している値を独立には知れないため、戻り先のEntraによる照合も重要です。

### 15.6 署名・issuer・audienceをローカルで検証する

以下は観察用の任意手順です。取得した返却トークンを、保護されたローカルファイル `returned-id-token.txt` に1行で保存し、有効期間内に実行します。トークンをコマンド履歴に直接書かないためにファイルを使います。

同じPowerShellで自分の `BaseUri` と `ClientId` を設定し、プロジェクトディレクトリから実行します。

```powershell
$env:LAB_PROVIDER_ISSUER = $BaseUri
$env:ENTRA_CLIENT_ID = $ClientId

@'
import json
import os
from pathlib import Path
import time

import jwt

issuer = os.environ["LAB_PROVIDER_ISSUER"]
audience = os.environ["ENTRA_CLIENT_ID"]
token = Path("returned-id-token.txt").read_text(encoding="utf-8").strip()
client = jwt.PyJWKClient(f"{issuer}/.well-known/jwks", timeout=10)
key = client.get_signing_key_from_jwt(token)
claims = jwt.decode(
    token,
    key.key,
    algorithms=["RS256"],
    issuer=issuer,
    audience=audience,
    options={"require": ["iss", "aud", "sub", "iat", "exp", "acr", "amr"]},
)
print("Signature, issuer, audience and lifetime: OK")
print("Seconds remaining:", claims["exp"] - int(time.time()))
print("acr:", claims["acr"], "amr:", json.dumps(claims["amr"]))
'@ | .\.venv\Scripts\python.exe -
```

このコマンドの `LAB_PROVIDER_ISSUER` は観察スクリプト専用です。アプリ本体の `ISSUER` 設定を変更するものではありません。

この検証だけではリクエストのnonceとの一致、stateの一致、Entraの全ポリシー充足までは確認しません。元の要求とフォームを別途照合します。期限切れなら検証を無効にせず、新しい認証フローで取り直します。

検証後は、このトークンファイルと不要なNetwork/HAR記録を削除します。

<a id="troubleshooting"></a>
## 16. トラブルシューティング

| 症状 | 主な確認事項 |
|---|---|
| Flask / Gunicornが起動しない | `private.pem` / `cert.pem` の存在・名前、RSAか、鍵が一致するか、ZIPの直下構造 |
| `No module named ...` | サーバー側ビルド有効、ルートの依存ファイル、Oryxのインストール結果 |
| Azureで既定ページや古い動作 | 対象Webアプリ、デプロイログ、Startup Command、最新ZIP |
| テンプレート関連の500 | `templates` とHTMLファイル2つをZIPへ入れたか |
| `/authorize` にブラウザーでアクセスすると405 | 正常。GETではなくEntraからのPOST用 |
| `/approve` が404 | 古いデプロイや別アプリへの送信 |
| `provider_not_configured` / 503 | テナントID・Client IDがGUIDか。環境変数による上書きも確認 |
| `invalid_request` / 400 | Client ID、固定のredirect URI、フォーム形式、重複パラメーター、要求claims |
| `invalid_id_token_hint` / 400 | 偽トークンなら期待どおり。本物ならissuer・audience・tenant・署名・時刻を確認 |
| `entra_metadata_unavailable` / 502 | App ServiceまたはローカルからのDiscovery/JWKS取得、TLS信頼、プロキシ、DNS、タイムアウト |
| `transaction_store_unavailable` / 503 | 一時ディレクトリへの書き込み、SQLite、ロック、ログストリーム |
| `invalid_transaction` / 400 | Cookie、同じブラウザー、期限、二重押下、再起動、スケールアウト |
| Entraで認可URL検証エラー、50161 | アプリ登録のWebリダイレクトURIとDiscoveryのauthorization_endpoint |
| Entraでservice principalがない旨、900491 | 対象テナントでのアプリの管理者同意 |
| ボタン後にEntraで署名検証エラー | `kid`、JWKSと秘密鍵の一致、issuer、古い鍵のキャッシュ |
| MFA選択肢に出ない | Enabled、Include/Exclude、グループ所属、ユーザーごとの登録、同意、要求の種類 |
| サインイン時にMFA画面自体が出ない | MFA要求の有無、既存セッション、既に満たされたMFA、パスワードレスの最初の要素 |
| 選べてもポリシーを満たせない | 認証強度ポリシー、許可されていない `acr` / `amr`、他のデバイス・リスク条件 |

### 16.1 MFAの選択肢に表示されない場合

次の順に確認します。

1. 正しいテナント・正しいテストユーザーか。
2. External MFAが有効で、同意がGrantedか。
3. Include対象に入り、Exclude対象ではないか。
4. ユーザーのUsable authentication methodsへ明示登録されているか。
5. 認証強度ではなく通常のMFA要求で試しているか。
6. 新しいInPrivateセッションでやり直したか。
7. 設定反映を待って再試行する。

反映時間には固定の保証値を置きません。「反映待ち」と決めつけて、ユーザー登録やポリシーの問題を見落とさないでください。

### 16.2 502が出た場合

App Serviceのログストリーム、またはローカルのFlaskターミナルで、`Entra metadata/signing-key retrieval failed` の後の例外名・理由を確認します。

- `Timeout`: 接続・プロキシ・一時的な遅延。
- TLS関連の例外: 実行環境の信頼ストアや、許可された企業プロキシの構成。
- HTTPエラー: URL、テナント、サービスからの応答。
- メタデータ不一致: コードが想定するGlobal Azure / v2.0 / 単一テナント構成か。

TLS検証を無効にしたり、JWT検証を飛ばして通したりしません。形式不正な `not-a-real-token` は通信前に400になるため、そのテストだけでは外部通信の正常性は分かりません。

### 16.3 証跡を共有する場合

共有するもの:

- エラーコードとメッセージ。
- 発生時刻とタイムゾーン。
- EntraのCorrelation ID。
- 個人情報・認証情報を除いた該当ログ。
- どのチェックポイントまで成功したか。

共有しないもの:

- 秘密鍵。
- JWTやCookieの全文。
- 未加工のHAR。
- 秘密鍵入りのデプロイZIP。

<a id="cleanup"></a>
## 17. ラボを停止・削除する

### 17.1 一旦ラボを止める

1. Entraの今回のExternal MFAを**Off**にします。
2. 専用に追加した条件付きアクセスポリシーがある場合だけ、そのポリシーをOffにします。既存ポリシーは変更しません。
3. 必要に応じてテストユーザーのExternal MFA登録を削除します。
4. App Serviceを停止します。

**App Serviceを停止しても、App Serviceプランの課金が止まるとは限りません。**

### 17.2 完全に破棄する

1. このラボ専用のExternal MFA設定と、ユーザーの登録を削除します。
2. このラボ専用の条件付きアクセスがあれば削除します。
3. このラボ専用のアプリ登録と関連するEnterprise applicationを確認して削除します。
4. 専用のWebアプリ、プラン、不要になった専用リソースグループをPortalで削除します。
5. ローカルの秘密鍵、証明書、秘密鍵入りZIP、取得JWT、不要なログを適切に処分します。

共有リソースグループや既存プランを丸ごと削除しないでください。削除画面で対象を確認し、このラボ専用のものだけを削除します。

<a id="checklist"></a>
## 18. 完了チェックリストと公式資料

### 18.1 完了チェックリスト

- [ ] 検証専用ユーザー・グループを用意した。
- [ ] Linux / PythonのApp Serviceと専用プランを作成した。
- [ ] 実際の既定ホスト名を記録した。
- [ ] 1インスタンス、HTTPS公開、Easy Authで遮断しない構成にした。
- [ ] アプリ登録に自分の `/authorize` をWebリダイレクトURIとして登録した。
- [ ] `openid` / `profile` と管理者同意を確認した。
- [ ] コードのissuer・テナントID・Client IDを自分の値に変更した。
- [ ] 自分のRSA秘密鍵と証明書を生成した。
- [ ] 自動テスト25件の `OK` を確認した。
- [ ] ローカルの4つのGETと偽トークン拒否を確認した。
- [ ] ZIP直下にコード、依存ファイル、鍵ペア、テンプレート2つを含めた。
- [ ] サーバー側ビルドとGunicornの設定を確認した。
- [ ] Azureの4つのGET、`/authorize` の400、`/approve` の400を確認した。
- [ ] EntraにExternal MFAを登録し、同意とテスト限定の有効化を確認した。
- [ ] テストユーザーの利用可能な認証方法にExternal MFAを登録した。
- [ ] 対象リソースで適切なMFA要求がある。
- [ ] 認証方法一覧にExternal MFAが表示された。
- [ ] 実際のEntra要求で承認画面が表示された。
- [ ] ボタン押下後、Entraへ戻ってサインインを完了した。
- [ ] サインインログで対象ユーザー・時刻・認証結果を確認した。
- [ ] 検証後の無効化・費用・鍵と証跡の扱いを確認した。

### 18.2 検証結果の記録欄

| 項目 | 記録 |
|---|---|
| 実施日・担当者 | |
| Pythonバージョン（ローカル / Azure） | |
| 主なライブラリバージョン | |
| App Service名・実際のホスト名 | |
| テナントID・Client ID | |
| テストユーザー・グループ | |
| 対象リソース・MFA要求元ポリシー | |
| External MFA表示名 | |
| ローカルテスト結果 | |
| Azure拒否テスト結果 | |
| エンドツーエンド結果・時刻 | |
| サインインログのCorrelation ID | |
| 停止・削除予定 | |

この表に秘密鍵やJWTの全文は記録しません。

### 18.3 公式資料

以下は本書作成時点で確認した資料です。External MFA固有の動作は、一般OIDCの推測ではなくMicrosoftのプロバイダー仕様を優先します。

1. [Microsoft Entra External MFA provider reference](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-external-method-provider)
2. [External MFAの管理・プロバイダー登録・ユーザー登録](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-external-method-manage)
3. [App ServiceへのPythonアプリのデプロイ](https://learn.microsoft.com/en-us/azure/app-service/quickstart-python)
4. [Linux Pythonアプリのランタイム・ビルド・起動設定](https://learn.microsoft.com/en-us/azure/app-service/configure-language-python)
5. [ZIPデプロイとサーバー側ビルド](https://learn.microsoft.com/en-us/azure/app-service/deploy-zip)
6. [Basic認証を無効にした状態でのデプロイ](https://learn.microsoft.com/en-us/azure/app-service/configure-basic-auth-disable)
7. [条件付きアクセスとライセンス要件](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview)
8. [条件付きアクセスのMFAポリシーとExternal MFAの認証強度制約](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-mfa-strength)

資料8は全ユーザー向けポリシーの解説ですが、本書のラボでは**全ユーザーに適用せず、テストグループ・テストリソースだけ**に限定します。また、同資料の注意書きどおり、External MFAにはRequire multifactor authenticationを使います。
