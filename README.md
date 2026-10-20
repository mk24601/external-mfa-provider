# Microsoft Entra External MFA — Button-only Lab

Microsoft Entra IDのExternal MFAプロトコルを学ぶための、Python / Flask製の最小ラボプロバイダーです。

Azure App Service（Linux）で動かし、Entraからの要求を検証した後、**承認ボタンを押すだけ**でRS256署名付きIDトークンを返します。

> **LAB ONLY — 実際のMFAは行いません。**
>
> このサンプルはOTPなどの追加認証を実行せず、模擬的に `acr=possessionorinherence`、`amr=["otp"]` を返します。本番認証や実業務リソースの保護には使用しないでください。Entra側の対象もテスト専用ユーザー／グループに限定します。

## はじめに読むもの

**[日本語の構築・検証マニュアル](./External-MFA-Lab-Manual.ja.md)**

App Service作成、アプリ登録、鍵生成、ZIPデプロイ、External MFA設定、ユーザー登録、サインインテストまでを、チェックポイント付きで説明しています。

コードを取得しただけでは起動しません。各自の環境設定と、各自で生成する鍵・証明書が必要です。

## 構成

```text
EntraでMFA要求
  → 外部MFAを選択
  → POST /authorize
  → id_token_hintとリクエストを検証
  → ラボ用の承認ボタン
  → POST /approve
  → RS256署名付きIDトークンをform_post
  → Entraが検証してサインインを継続
```

## ファイル

| ファイル | 内容 |
|---|---|
| [app.py](./external-mfa-provider/app.py) | Flaskエンドポイント、検証、一時保存、署名 |
| [requirements.txt](./external-mfa-provider/requirements.txt) | Python依存関係 |
| [authorize.html](./external-mfa-provider/templates/authorize.html) | 承認画面 |
| [form_post.html](./external-mfa-provider/templates/form_post.html) | Entraへの自動フォームPOST |
| [test_app.py](./external-mfa-provider/test_app.py) | 自動テスト |
| [詳細マニュアル](./External-MFA-Lab-Manual.ja.md) | Azure / Entraを含む全手順 |

`private.pem` と `cert.pem` は、マニュアルに従って自分の環境で生成してください。

## 必要な環境

- AzureサブスクリプションとLinux App Service。検証時のAzureランタイムはPython 3.14。
- 検証用Entraテナント、テストユーザー、必要な管理権限。
- 条件付きアクセスでMFA要求を作る場合は、適切なP1以上のライセンス。
- ローカルのPython、PowerShell、必要に応じてAzure CLI。
- App Serviceは**1インスタンス**。一時保存先のSQLiteは分散データベースではありません。

## 設定する3項目

| 項目 | 現行コードでの指定方法 |
|---|---|
| `ISSUER` | 自分のApp ServiceのHTTPS URLをコード内定数に指定。末尾 `/` なし |
| `ENTRA_TENANT_ID` | 環境変数、またはコード内の既定値 |
| `ENTRA_CLIENT_ID` | 環境変数、またはコード内の既定値 |

**現行コードは `ISSUER` 環境変数を読みません。** 3項目とも環境変数だけで変更できる実装ではありません。

[マニュアル第6章](./External-MFA-Lab-Manual.ja.md#code-settings)に従い、設定値を自分の環境に合わせて変更してください。

## 構築の順番

1. テストユーザー／グループとApp Serviceを作成する。
2. 自分の `/authorize` をWebリダイレクトURIにしたEntraアプリを登録する。
3. `openid` / `profile` と管理者同意を設定する。
4. コードの環境値を変更し、Python環境とRSA鍵・証明書を準備する。
5. ローカルの自動テストとHTTP確認を行う。
6. 各自の鍵を含む**デプロイ専用ZIP**を作り、App Serviceへデプロイする。
7. EntraにExternal MFAを登録し、テストユーザーに認証方法を登録する。
8. 適切なMFA要求で外部MFAを選び、ボタン承認後にサインインが継続することを確認する。

**GitHubのDownload ZIPは、デプロイ専用ZIPではありません。** 展開して上記の準備を済ませ、マニュアル第9章の方法でZIPを作り直してください。

## ローカルテスト

自分の環境値、仮想環境、依存関係、`private.pem` / `cert.pem` の準備が終わった後、プロジェクトディレクトリで実行します。

```powershell
Set-Location .\external-mfa-provider
.\.venv\Scripts\python.exe -B -m unittest test_app -v
.\.venv\Scripts\python.exe .\app.py
```

テストは本書作成時点で25件です。正しい署名の受け入れ、不正な入力の拒否、承認の一回限りの使用、返却JWTとJWKSの整合性などを確認します。

テスト内ではEntra公開鍵の取得を差し替えます。実際のEntra連携の成功は、別途サインインテストで確認してください。

## プロトコル上の注意

- `id_token_hint` の署名・issuer・audience・テナントなどを検証します。
- MicrosoftのExternal MFA仕様に合わせ、ヒントの期限切れは許容します。返却トークンの有効期限を無視するという意味ではありません。
- `sub` は検証済みヒントから引き継ぎます。
- `nonce` は返却JWT、`state` は返却フォームに引き継ぎます。
- `kid` はJWTヘッダーと公開JWKSで一致させます。JWKSには `x5c` も含めます。
- 固定の模擬 `acr` / `amr` を許可しないリクエストは拒否します。
- External MFAの有効化だけではMFA要求は発生しません。
- Microsoftの現行資料では、認証強度ではなく **Require multifactor authentication** の許可制御を使います。

## 利用上の注意

- 自分のApp Service、アプリ登録、鍵ペアを作成します。
- 秘密鍵やJWT、Cookie、HARなどの認証関連情報は安全に管理してください。
- 検証後はラボのExternal MFAを無効にし、不要なリソースと認証記録を処分します。
- App Serviceの停止だけではプランの課金が止まるとは限りません。

## 公式資料

- [Microsoft Entra External MFA provider reference](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-external-method-provider)
- [External MFAの管理とユーザー登録](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-external-method-manage)
- [Azure App ServiceのPython設定](https://learn.microsoft.com/en-us/azure/app-service/configure-language-python)

文書更新日: 2026-10-20
