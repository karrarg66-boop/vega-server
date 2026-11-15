# VEGA Server — المرحلة الأولى (Backend Starter)

هذا مشروع خادم أولي قابل للتشغيل والتطوير، وليس خدمة مستضافة ولا APK. واجهتا VEGA V12 وVEGA Admin V4 ما زالتا ملفات معاينة مستقلة، ولم تُربطا بهذا الخادم بعد.

## الموجود فعلياً
- حساب مدير يُنشأ عند التشغيل الأول من متغيرات البيئة.
- تسجيل دخول بإصدار JWT صالح 8 ساعات، وكلمات مرور المستخدمين محفوظة بـ PBKDF2-SHA256 مع salt مختلف لكل حساب.
- المدير ينشئ حساب المستخدم ويحدد كلمة مروره بنفسه، ويُسند له جهازاً أو أكثر، ويغير كلمة المرور أو يعطل الحساب.
- المدير يضيف MikroTik بعنوان الاتصال، اسم حساب الراوتر وكلمة مروره؛ كلمة مرور الراوتر تُشفّر بـ Fernet في قاعدة SQLite.
- المستخدم يشوف فقط الأجهزة المخصصة له، بدون عنوان IP أو كلمة مرور الراوتر.
- استعلام مباشر لـ RouterOS API-SSL (المنفذ 8729) عن موارد الجهاز والمنافذ؛ الاتصال يتحقق من شهادة TLS.
- سجل تدقيق بسيط لعمليات الإدارة.

## التشغيل المحلي على كمبيوتر أو خادم Linux

```bash
cd VEGA_Server_Starter
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

انسخ المفتاح الناتج وضعه في `VEGA_ENCRYPTION_KEY`، ثم شغّل بعد اختيار كلمة سر قوية:

```bash
export VEGA_JWT_SECRET='PUT_A_RANDOM_SECRET_OF_AT_LEAST_32_CHARACTERS_HERE'
export VEGA_ENCRYPTION_KEY='PASTE_THE_GENERATED_FERNET_KEY_HERE'
export VEGA_INITIAL_ADMIN='admin'
export VEGA_INITIAL_ADMIN_PASSWORD='CHANGE_THIS_TO_A_LONG_UNIQUE_PASSWORD'
uvicorn server:app --host 127.0.0.1 --port 8000
```

يمكن اختبار تسجيل الدخول عبر طلب HTTP محلي:

```bash
curl -s http://127.0.0.1:8000/api/login -H 'Content-Type: application/json' -d '{"username":"admin","password":"CHANGE_THIS_TO_A_LONG_UNIQUE_PASSWORD"}'
```

انسخ `access_token` واستخدمه في ترويسة `Authorization: Bearer <TOKEN>` للطلبات التالية.

## أهم المسارات

- `POST /api/login` — تسجيل الدخول.
- `GET /api/me` — الحساب الحالي.
- `POST /api/admin/devices` — إضافة جهاز؛ حقول `name, model, host, port, router_user, router_password`.
- `GET /api/admin/devices` — أجهزة المدير وعناوينها (بدون كلمات المرور).
- `POST /api/admin/users` — إضافة مستخدم؛ حقول `full_name, username, password, device_ids, enabled`.
- `GET /api/admin/users` — قائمة المستخدمين وأجهزتهم.
- `PUT /api/admin/users/{id}/assignments` — تغيير الأجهزة، مثال `{"device_ids":[1,2]}`.
- `PUT /api/admin/users/{id}/password` — تغيير كلمة المرور.
- `PUT /api/admin/users/{id}/enabled/false` — تعطيل المستخدم.
- `GET /api/devices` — الأجهزة المسموحة للحساب الحالي.
- `GET /api/devices/{id}/status` — موارد الراوتر ومنافذه من API-SSL.
- `GET /api/admin/audit` — سجل عمليات الإدارة.

## متطلبات MikroTik

أنشئ مستخدم RouterOS منفصلاً بصلاحية `read` فقط قدر الإمكان مع صلاحيات API الضرورية، ولا تستخدم حساب `admin` الأساسي. فعّل `api-ssl` بشهادة موثوقة يتحقق منها الخادم؛ تأكد من أن اسم الشهادة يطابق اسم المضيف، ومن إعداد الثقة في شهادة الجهة المصدرة على الخادم. اجعل وصول المنفذ 8729 محصوراً بخادم VEGA عبر شبكة VPN أو شبكة خاصة، ولا تفتح المنفذ للعالم. اختبار الاتصال الفعلي يحتاج جهازاً متاحاً وإعداد TLS صحيحاً.

## قبل النشر للمستخدمين

هذه **بداية تطوير** وليست جاهزة للإنتاج: تحتاج لوحة إدارة ويب مرتبطة بهذه المسارات، وربط تطبيق أندرويد بواجهة API، HTTPS أمام الخادم، قاعدة PostgreSQL بدل SQLite عند التوسع، نسخاً احتياطية، حماية محاولات تسجيل الدخول، جلسات قابلة للإبطال، مراقبة وأخطاء وسجلات منظمة، إدارة شهادات، سياسات كلمات مرور، تقييد شبكة الخادم، اختبار أداء، وتدقيق أمني. تعطيل الحساب يمنع الطلبات التالية فوراً؛ تغيير كلمة المرور لا يلغي JWT الصادر سابقاً حتى تنتهي صلاحيته (8 ساعات) في هذه النسخة.

**لا ترفع ملف `.db` أو مفتاح التشفير إلى مستودع عام.**
