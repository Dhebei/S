const express = require('express');
const { Client, GatewayIntentBits, Partials } = require('discord.js');
const bodyParser = require('body-parser');
const path = require('path');
const axios = require('axios');
const { joinVoiceChannel, entersState, VoiceConnectionStatus } = require('@discordjs/voice');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const bcrypt = require('bcrypt');

const app = express();
const port = 10015;

// =========================================================================
// التكوين الأساسي - تأكد من تغيير هذه القيم!
// =========================================================================

const WEBHOOK_URL = 'https://discord.com/api/webhooks/1372055031771168778/dYIrzRLg6bu3_uRJ9EUC7dpgKM8A0pKjiDfVTd_p5tFsHdEdJasENR_A8YwbFa2YPMzM'; // *** استبدل هذا بعنوان الويب هوك الخاص بك ***
// مفتاح سري للجلسات - مهم جداً! قم بتوليد مفتاح عشوائي وقوي جداً
// استخدم أمراً مثل 'openssl rand -base64 32' في Terminal أو Node.js لإنشاء مفتاح آمن
const SESSION_SECRET = 'd4c3a2b1e0f9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3';

if (WEBHOOK_URL === 'YOUR_DISCORD_WEBHOOK_URL_HERE' || !WEBHOOK_URL) {
    console.warn('تحذير: لم يتم تعيين WEBHOOK_URL. لن يتم إرسال رسائل الويب هوك.');
}
if (SESSION_SECRET === 'your_super_secret_session_key_here_please_change_this_to_a_random_string_!!!!!') {
    console.error('تحذير خطير: SESSION_SECRET لم يتم تغييره! يرجى توليد مفتاح سري عشوائي وقوي لضمان أمان الجلسات.');
}

// =========================================================================
// إعدادات Express و Middleware
// =========================================================================

app.use(bodyParser.json());
// لتمكين الوصول إلى ملفات static مثل HTML و CSS من مجلد public
app.use(express.static(path.join(__dirname, 'public')));

// إعدادات الجلسة
app.use(session({
    secret: SESSION_SECRET,
    resave: false, // لا تحفظ الجلسة إذا لم يتم تعديلها
    saveUninitialized: false, // لا تحفظ الجلسة غير المهيئة
    cookie: { 
        secure: process.env.NODE_ENV === 'production', // استخدم secure: true في الإنتاج مع HTTPS
        maxAge: 24 * 60 * 60 * 1000 // مدة صلاحية الكوكي: 24 ساعة
    }
}));

// =========================================================================
// إعداد قاعدة البيانات SQLite
// =========================================================================
const db = new sqlite3.Database(path.join(__dirname, 'data.db'), (err) => {
    if (err) {
        console.error('فشل الاتصال بقاعدة البيانات:', err.message);
    } else {
        console.log('تم الاتصال بقاعدة بيانات data.db بنجاح.');
        // جدول للمستخدمين
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )`, (err) => {
            if (err) {
                console.error('فشل إنشاء جدول المستخدمين:', err.message);
            } else {
                console.log('جدول المستخدمين جاهز أو تم إنشاؤه.');
            }
        });

        // جدول للبوتات (يربط كل بوت بمعرف المستخدم الذي أضافه)
        db.run(`CREATE TABLE IF NOT EXISTS bots (
            id TEXT PRIMARY KEY,
            token TEXT NOT NULL,
            name TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )`, (err) => {
            if (err) {
                console.error('فشل إنشاء جدول البوتات:', err.message);
            } else {
                console.log('جدول البوتات جاهز أو تم إنشاؤه.');
            }
        });
    }
});

// =========================================================================
// إدارة البوتات النشطة والاتصالات الصوتية
// =========================================================================
const activeBots = new Map(); // Map<botId, Discord.Client>
const activeConnections = new Map(); // Map<botId, VoiceConnection>

// إغلاق جميع البوتات عند إغلاق الخادم
process.on('SIGINT', async () => {
    console.log('جاري إغلاق الخادم. فصل جميع البوتات...');
    for (const [botId, client] of activeBots.entries()) {
        try {
            if (activeConnections.has(botId)) {
                activeConnections.get(botId).destroy();
                activeConnections.delete(botId);
            }
            if (client && client.isReady()) {
                await client.destroy();
            }
            console.log(`تم فصل البوت ${client ? client.user.tag : botId}`);
        } catch (e) {
            console.error(`فشل فصل البوت ${botId}:`, e.message);
        }
    }
    db.close((err) => {
        if (err) {
            console.error('فشل إغلاق قاعدة البيانات:', err.message);
        } else {
            console.log('تم إغلاق قاعدة البيانات.');
        }
        process.exit(0);
    });
});

// =========================================================================
// Middleware للتحقق من المصادقة
// =========================================================================
function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        next(); // المستخدم مصادق عليه
    } else {
        // إذا كان الطلب API، أرسل 401. إذا كان طلب صفحة HTML، أعد التوجيه لصفحة تسجيل الدخول
        if (req.xhr || req.headers.accept.indexOf('json') > -1) { // تحقق إذا كان طلب Ajax
            res.status(401).json({ message: 'غير مصرح لك. يرجى تسجيل الدخول.' });
        } else {
            res.redirect('/login');
        }
    }
}

// =========================================================================
// دوال Webhook لإرسال الإشعارات
// =========================================================================
async function sendWebhookMessage(embeds, content = '', username = 'Bot Status Notifier', avatar_url = '') {
    if (!WEBHOOK_URL || WEBHOOK_URL === 'YOUR_DISCORD_WEBHOOK_URL_HERE') {
        console.warn('لم يتم تعيين WEBHOOK_URL، لا يمكن إرسال رسالة الويب هوك.');
        return;
    }
    try {
        await axios.post(WEBHOOK_URL, {
            content: content,
            username: username,
            avatar_url: avatar_url,
            embeds: Array.isArray(embeds) ? embeds : [embeds]
        });
        console.log('تم إرسال رسالة Webhook (Embed) بنجاح.');
    } catch (error) {
        console.error('فشل إرسال رسالة Webhook (Embed):', error.response ? error.response.data : error.message);
    }
}

// =========================================================================
// API للمصادقة (تسجيل، دخول، خروج، المستخدم الحالي)
// =========================================================================

// تسجيل مستخدم جديد
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).send('الرجاء توفير اسم المستخدم وكلمة المرور.');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10); // تجزئة كلمة المرور

        db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashedPassword], function (err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed: users.username')) {
                    return res.status(409).send('اسم المستخدم موجود بالفعل.');
                }
                res.status(500).json({ error: err.message });
                return;
            }
            res.status(201).send('تم إنشاء الحساب بنجاح. يمكنك الآن تسجيل الدخول.');
            sendWebhookMessage({
                color: 0x00BFFF, // أزرق فاتح
                title: '✨ حساب جديد مسجل',
                description: `تم إنشاء حساب مستخدم جديد: \`${username}\`.`,
                timestamp: new Date()
            });
        });
    } catch (error) {
        console.error('فشل تسجيل المستخدم:', error.message);
        res.status(500).send('حدث خطأ أثناء إنشاء الحساب.');
    }
});

// تسجيل دخول المستخدم
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).send('الرجاء توفير اسم المستخدم وكلمة المرور.');
    }

    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (!user) {
            return res.status(401).send('اسم المستخدم أو كلمة المرور غير صحيحة.');
        }

        const match = await bcrypt.compare(password, user.password);
        if (match) {
            req.session.userId = user.id;
            req.session.username = user.username;
            res.status(200).send('تم تسجيل الدخول بنجاح.');
            sendWebhookMessage({
                color: 0x57F287, // أخضر فاتح
                title: '🔑 تسجيل دخول ناجح',
                description: `قام المستخدم \`${user.username}\` بتسجيل الدخول بنجاح.`,
                timestamp: new Date()
            });
        } else {
            res.status(401).send('اسم المستخدم أو كلمة المرور غير صحيحة.');
        }
    });
});

// تسجيل خروج المستخدم
app.post('/api/logout', isAuthenticated, (req, res) => {
    const username = req.session.username || 'مجهول';
    req.session.destroy(err => {
        if (err) {
            console.error('فشل تسجيل الخروج:', err);
            return res.status(500).send('فشل تسجيل الخروج.');
        }
        res.status(200).send('تم تسجيل الخروج بنجاح.');
        sendWebhookMessage({
            color: 0xED4245, // أحمر
            title: '🚪 تسجيل خروج',
            description: `قام المستخدم \`${username}\` بتسجيل الخروج.`,
            timestamp: new Date()
        });
    });
});

// جلب معلومات المستخدم الحالي
app.get('/api/current-user', (req, res) => {
    if (req.session.userId && req.session.username) {
        res.json({ userId: req.session.userId, username: req.session.username });
    } else {
        res.status(401).json({ message: 'غير مصادق عليه.' });
    }
});

// =========================================================================
// API لإدارة البوتات (يتطلب المصادقة)
// =========================================================================

// جلب جميع البوتات المرتبطة بالمستخدم الحالي
app.get('/api/bots', isAuthenticated, (req, res) => {
    const userId = req.session.userId;
    db.all("SELECT id, name FROM bots WHERE user_id = ?", [userId], (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json({ bots: rows });
    });
});

// إضافة بوت جديد
app.post('/api/bots/add', isAuthenticated, async (req, res) => {
    const { id, token, name } = req.body;
    const userId = req.session.userId;
    const username = req.session.username;

    if (!id || !token || !name) {
        return res.status(400).send('الرجاء توفير معرف البوت، التوكن، والاسم.');
    }

    // تحقق من أن البوت يعمل بالتوكن المقدم
    try {
        const tempClient = new Client({ intents: [GatewayIntentBits.Guilds] });
        await tempClient.login(token);
        // انتظر قليلاً لضمان أن البوت أصبح جاهزاً
        await new Promise(resolve => setTimeout(resolve, 1000));
        if (!tempClient.isReady() || tempClient.user.id !== id) {
            tempClient.destroy();
            return res.status(400).send('معرف البوت لا يتطابق مع التوكن، أو التوكن غير صالح.');
        }
        tempClient.destroy(); // فصل البوت المؤقت

    } catch (error) {
        console.error('فشل التحقق من التوكن:', error.message);
        return res.status(400).send(`فشل التحقق من التوكن: ${error.message}. يرجى التأكد من صحة التوكن و ID البوت.`);
    }

    // التحقق مما إذا كان هذا البوت موجودًا بالفعل لهذا المستخدم
    db.get("SELECT id FROM bots WHERE id = ? AND user_id = ?", [id, userId], (err, row) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (row) {
            return res.status(409).send('هذا البوت (ID) موجود بالفعل لحسابك.');
        }

        // إضافة البوت مع user_id
        db.run(`INSERT INTO bots (id, token, name, user_id) VALUES (?, ?, ?, ?)`, [id, token, name, userId], function (err) {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            res.status(201).send(`تم إضافة البوت ${name} بنجاح لحسابك.`);
            sendWebhookMessage({
                color: 0x00FF00,
                title: '➕ تم إضافة بوت جديد',
                description: `تم إضافة بوت جديد بواسطة المستخدم \`${username}\` (ID: \`${userId}\`).`,
                fields: [
                    { name: 'اسم البوت', value: `\`${name}\``, inline: true },
                    { name: 'معرف البوت (ID)', value: `\`${id}\``, inline: true }
                ],
                timestamp: new Date()
            });
        });
    });
});

// حذف بوت
app.delete('/api/bots/delete/:id', isAuthenticated, (req, res) => {
    const { id } = req.params;
    const userId = req.session.userId;
    const username = req.session.username;

    db.run(`DELETE FROM bots WHERE id = ? AND user_id = ?`, [id, userId], function (err) {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        if (this.changes === 0) {
            return res.status(404).send('البوت غير موجود لحسابك، أو لا تملك صلاحية حذفه.');
        }

        // فصل البوت إذا كان متصلاً حاليًا
        if (activeConnections.has(id)) {
            activeConnections.get(id).destroy();
            activeConnections.delete(id);
        }
        if (activeBots.has(id)) {
            const client = activeBots.get(id);
            if (client && client.isReady()) {
                client.destroy();
            }
            activeBots.delete(id);
        }

        res.status(200).send(`تم حذف البوت (ID: ${id}) بنجاح من حسابك.`);
        sendWebhookMessage({
            color: 0xFF0000,
            title: '➖ تم حذف بوت',
            description: `تم حذف بوت بواسطة المستخدم \`${username}\` (ID: \`${userId}\`).`,
            fields: [
                { name: 'معرف البوت (ID)', value: `\`${id}\``, inline: true }
            ],
            timestamp: new Date()
        });
    });
});

// =========================================================================
// API للتحكم بالصوت (يتطلب المصادقة)
// =========================================================================
app.post('/join-voice', isAuthenticated, async (req, res) => {
    const { botId, channelId } = req.body;
    const userId = req.session.userId;
    const username = req.session.username;

    if (!botId || !channelId) {
        return res.status(400).send('الرجاء توفير معرف البوت ومعرف القناة.');
    }

    // تحقق من أن البوت ينتمي إلى هذا المستخدم
    db.get("SELECT token, name FROM bots WHERE id = ? AND user_id = ?", [botId, userId], async (err, row) => {
        if (err) {
            console.error('خطأ في جلب التوكن من قاعدة البيانات:', err.message);
            return res.status(500).send('فشل في الوصول إلى معلومات البوت.');
        }
        if (!row) {
            return res.status(404).send('البوت المحدد غير موجود لحسابك، أو لا تملك صلاحية استخدامه.');
        }

        const botToken = row.token;
        let botName = row.name || 'غير معروف';

        // إذا كان البوت متصلاً بالفعل، قم بفصله أولاً
        if (activeConnections.has(botId)) {
            const existingConnection = activeConnections.get(botId);
            if (existingConnection.state.status !== VoiceConnectionStatus.Destroyed) {
                existingConnection.destroy();
                activeConnections.delete(botId);
                console.log(`البوت ${botId} تم فصله من القناة السابقة قبل الاتصال بقناة جديدة.`);
            }
        }

        let client = activeBots.get(botId);
        let botTag = 'غير معروف';

        // إذا لم يكن البوت مسجل الدخول، قم بتسجيل الدخول
        if (!client || !client.isReady()) {
            client = new Client({
                intents: [
                    GatewayIntentBits.Guilds,
                    GatewayIntentBits.GuildMessages,
                    GatewayIntentBits.GuildVoiceStates,
                    GatewayIntentBits.MessageContent
                ],
                partials: [Partials.Channel]
            });

            client.once('ready', () => {
                console.log(`البوت مسجل الدخول: ${client.user.tag}`);
                activeBots.set(botId, client);
                botTag = client.user.tag;
            });

            try {
                await client.login(botToken);
                await new Promise(resolve => setTimeout(resolve, 1000)); // انتظر قليلاً
                if (client.isReady()) {
                    botTag = client.user.tag;
                } else {
                    throw new Error('البوت لم يصبح جاهزًا بعد تسجيل الدخول.');
                }
            } catch (error) {
                console.error('فشل تسجيل دخول البوت:', error);
                if (client && !client.isReady()) {
                     client.destroy();
                }
                activeBots.delete(botId);
                return res.status(500).send(`فشل تسجيل دخول البوت: ${error.message}. تأكد من صحة التوكن والـ Intents (خاصة Guilds و GuildVoiceStates).`);
            }
        } else {
            botTag = client.user.tag;
        }

        try {
            const channel = await client.channels.fetch(channelId);

            if (!channel || channel.type !== 2) { // Discord.ChannelType.GuildVoice = 2
                return res.status(400).send('معرف القناة غير صالح أو ليست قناة صوتية.');
            }

            const connection = joinVoiceChannel({
                channelId: channel.id,
                guildId: channel.guild.id,
                adapterCreator: channel.guild.voiceAdapterCreator,
                selfDeaf: false,
                selfMute: false,
            });

            activeConnections.set(botId, connection);

            connection.on(VoiceConnectionStatus.Ready, () => {
                console.log(`Connection is ready for ${botTag} in channel ${channel.name}!`);
                sendWebhookMessage({
                    color: 0x7289DA,
                    title: '✅ تم الانضمام إلى القناة الصوتية',
                    description: `البوت **${botTag}** انضم إلى القناة الصوتية بنجاح بواسطة المستخدم \`${username}\`.`,
                    fields: [
                        { name: 'اسم البوت', value: `\`${botName}\``, inline: true },
                        { name: 'القناة الصوتية', value: `\`#${channel.name}\``, inline: true },
                        { name: 'معرف القناة', value: `\`${channel.id}\``, inline: true },
                        { name: 'السيرفر', value: `\`${channel.guild.name}\``, inline: true },
                        { name: 'معرف السيرفر', value: `\`${channel.guild.id}\``, inline: true }
                    ],
                    timestamp: new Date(),
                    footer: { text: `تم بواسطة لوحة التحكم` }
                });
            });

            connection.on(VoiceConnectionStatus.Disconnected, async (oldState, newState) => {
                if (newState.status === VoiceConnectionStatus.Disconnected) {
                    try {
                        // حاول إعادة الاتصال لمدة 5 ثوانٍ
                        await Promise.race([
                            entersState(connection, VoiceConnectionStatus.Connecting, 5_000),
                            entersState(connection, VoiceConnectionStatus.Ready, 5_000),
                        ]);
                    } catch (error) {
                        // إذا فشلت إعادة الاتصال بعد 5 ثوانٍ
                        if (activeConnections.has(botId)) {
                            activeConnections.delete(botId);
                            connection.destroy();
                            console.log(`البوت ${botTag} تم فصله من القناة الصوتية ولم يتمكن من إعادة الاتصال.`);
                            sendWebhookMessage({
                                color: 0xFEE75C,
                                title: '⚠️ البوت غادر القناة الصوتية',
                                description: `البوت **${botTag}** غادر القناة الصوتية (فصل أو فشل إعادة الاتصال) بواسطة المستخدم \`${username}\`.`,
                                fields: [
                                    { name: 'اسم البوت', value: `\`${botName}\``, inline: true },
                                    { name: 'السيرفر', value: `\`${channel.guild.name}\``, inline: true },
                                    { name: 'معرف السيرفر', value: `\`${channel.guild.id}\``, inline: true }
                                ],
                                timestamp: new Date(),
                                footer: { text: `تم بواسطة لوحة التحكم` }
                            });
                        }
                    }
                }
            });

            res.status(200).send(`تم ربط البوت ${botName} بالقناة الصوتية: ${channel.name}`);

        } catch (error) {
            console.error('فشل الربط بالقناة الصوتية:', error);
            if (activeConnections.has(botId)) {
                activeConnections.get(botId).destroy();
                activeConnections.delete(botId);
            }
            res.status(500).send(`فشل الربط بالقناة الصوتية: ${error.message}. تأكد من صلاحيات البوت في السيرفر والقناة.`);
        }
    });
});

app.post('/leave-voice', isAuthenticated, async (req, res) => {
    const { botId } = req.body;
    const userId = req.session.userId;
    const username = req.session.username;

    if (!botId) {
        return res.status(400).send('الرجاء توفير معرف البوت.');
    }

    // تأكد من أن البوت ينتمي إلى هذا المستخدم قبل محاولة فصله
    db.get("SELECT name FROM bots WHERE id = ? AND user_id = ?", [botId, userId], async (err, row) => {
        if (err) {
            console.error('خطأ في جلب اسم البوت من قاعدة البيانات:', err.message);
            return res.status(500).send('فشل في الوصول إلى معلومات البوت.');
        }
        if (!row) {
            return res.status(404).send('البوت المحدد غير موجود لحسابك، أو لا تملك صلاحية فصله.');
        }

        const botName = row.name || 'غير معروف';
        const connection = activeConnections.get(botId);
        const client = activeBots.get(botId);
        let botTag = client ? client.user.tag : 'غير معروف';

        if (connection) {
            try {
                connection.destroy();
                activeConnections.delete(botId);

                // دمر عميل البوت فقط إذا لم يكن متصلاً بقنوات أخرى أو لم نعد نحتاجه.
                // في هذا السيناريو، طالما أنه تم فصله، يمكننا تدميره.
                if (client && client.isReady()) {
                    client.destroy();
                }
                activeBots.delete(botId);

                sendWebhookMessage({
                    color: 0xED4245,
                    title: '❌ تم فصل البوت من القناة الصوتية',
                    description: `البوت **${botTag || botName}** غادر القناة الصوتية بنجاح بواسطة المستخدم \`${username}\`.`,
                    fields: [
                        { name: 'اسم البوت', value: `\`${botName}\``, inline: true },
                        { name: 'معرف البوت', value: `\`${botId}\``, inline: true }
                    ],
                    timestamp: new Date(),
                    footer: { text: `تم بواسطة لوحة التحكم` }
                });
                res.status(200).send('تم فصل البوت بنجاح.');
            } catch (error) {
                console.error('فشل فصل البوت:', error);
                res.status(500).send(`فشل فصل البوت: ${error.message}`);
            }
        } else {
            res.status(404).send('البوت غير متصل حاليًا بأي قناة صوتية.');
        }
    });
});


// =========================================================================
// API للبرودكاست (يتطلب المصادقة)
// =========================================================================
app.post('/send-private-broadcast', isAuthenticated, async (req, res) => {
    const { botId, guildId, message } = req.body;
    const userId = req.session.userId;
    const username = req.session.username;

    if (!botId || !guildId || !message) {
        return res.status(400).send('الرجاء توفير معرف البوت، معرف السيرفر، والرسالة.');
    }

    // تحقق من أن البوت ينتمي إلى هذا المستخدم
    db.get("SELECT token, name FROM bots WHERE id = ? AND user_id = ?", [botId, userId], async (err, row) => {
        if (err) {
            console.error('خطأ في جلب التوكن من قاعدة البيانات:', err.message);
            return res.status(500).send('فشل في الوصول إلى معلومات البوت.');
        }
        if (!row) {
            return res.status(404).send('البوت المحدد غير موجود لحسابك، أو لا تملك صلاحية استخدامه.');
        }

        const botToken = row.token;
        let botName = row.name || 'غير معروف';

        let client = activeBots.get(botId);
        let botTag = 'غير معروف';

        const requiredIntents = [
            GatewayIntentBits.Guilds,
            GatewayIntentBits.GuildMembers, // مطلوب لجلب الأعضاء
            GatewayIntentBits.MessageContent,
            GatewayIntentBits.GuildVoiceStates
        ];

        // إذا لم يكن البوت مسجل الدخول، قم بتسجيل الدخول
        if (!client || !client.isReady()) {
            client = new Client({
                intents: requiredIntents,
                partials: [Partials.Channel, Partials.GuildMember] // مطلوب لـ GuildMembers
            });

            try {
                await client.login(botToken);
                activeBots.set(botId, client);
                await new Promise(resolve => setTimeout(resolve, 1000));
                if (client.isReady()) {
                    botTag = client.user.tag;
                } else {
                    throw new Error('البوت لم يصبح جاهزًا بعد تسجيل الدخول لإرسال الرسالة الخاصة.');
                }
            } catch (error) {
                console.error('فشل تسجيل دخول البوت لإرسال الرسالة الخاصة:', error);
                if (client && !client.isReady()) {
                    client.destroy();
                }
                activeBots.delete(botId);
                return res.status(500).send(`فشل تسجيل دخول البوت: ${error.message}. تأكد من تفعيل Guild Members Intent لبوتك.`);
            }
        } else {
            botTag = client.user.tag;
        }

        try {
            const guild = await client.guilds.fetch(guildId);
            if (!guild) {
                return res.status(400).send('معرف السيرفر غير صالح أو البوت ليس في هذا السيرفر.');
            }

            // جلب جميع الأعضاء للتأكد من أن الكاش محدث
            if (guild.memberCount !== guild.members.cache.size) {
                await guild.members.fetch({ force: true }); // force: true لضمان التحديث
            }

            let sentCount = 0;
            let failedCount = 0;
            const membersToSendTo = guild.members.cache.filter(member => !member.user.bot);
            const totalMembers = membersToSendTo.size;

            sendWebhookMessage({
                color: 0xFEE75C,
                title: '✉️ بدء إرسال رسائل خاصة',
                description: `البوت **${botTag}** بدأ بإرسال رسالة خاصة لجميع الأعضاء غير البوتات في السيرفر بواسطة المستخدم \`${username}\`.`,
                fields: [
                    { name: 'اسم البوت', value: `\`${botName}\``, inline: true },
                    { name: 'السيرفر', value: `\`${guild.name}\` (ID: \`${guildId}\`)`, inline: false },
                    { name: 'إجمالي الأعضاء (غير البوتات)', value: `\`${totalMembers}\``, inline: true },
                    { name: 'محتوى الرسالة', value: `\`\`\`\n${message}\n\`\`\``, inline: false }
                ],
                timestamp: new Date(),
                footer: { text: `تم بواسطة لوحة التحكم` }
            });

            for (const member of membersToSendTo.values()) {
                try {
                    await member.send(message);
                    sentCount++;
                    await new Promise(resolve => setTimeout(resolve, 500)); // تأخير 500ms لتجنب Rate Limit
                } catch (dmError) {
                    console.error(`فشل إرسال رسالة خاصة للعضو ${member.user.tag}:`, dmError.message);
                    failedCount++;
                }
            }

            sendWebhookMessage({
                color: 0x57F287,
                title: '✅ انتهى إرسال الرسائل الخاصة',
                description: `البوت **${botTag}** انتهى من إرسال الرسائل الخاصة في السيرفر \`${guild.name}\` بواسطة المستخدم \`${username}\`.`,
                fields: [
                    { name: 'اسم البوت', value: `\`${botName}\``, inline: true },
                    { name: 'تم الإرسال بنجاح', value: `\`${sentCount}\``, inline: true },
                    { name: 'فشل الإرسال', value: `\`${failedCount}\``, inline: true }
                ],
                timestamp: new Date(),
                footer: { text: `تم بواسطة لوحة التحكم` }
            });
            res.status(200).send(`تم إرسال الرسالة إلى ${sentCount} عضو بنجاح. فشل إرسالها إلى ${failedCount} عضو.`);

        } catch (error) {
            console.error('فشل إرسال الرسالة الخاصة لجميع الأعضاء:', error);
            sendWebhookMessage({
                color: 0xED4245,
                title: '❌ فشل إرسال رسائل خاصة',
                description: `البوت **${botTag}** فشل في إرسال الرسائل الخاصة في السيرفر \`${guildId}\` بواسطة المستخدم \`${username}\`.`,
                fields: [
                    { name: 'اسم البوت', value: `\`${botName}\``, inline: true },
                    { name: 'الخطأ', value: `\`\`\`\n${error.message}\n\`\`\``, inline: false },
                    { name: 'تلميح', value: 'تأكد من أن البوت في السيرفر ومن تفعيل Guild Members Intent.', inline: false }
                ],
                timestamp: new Date(),
                footer: { text: `تم بواسطة لوحة التحكم` }
            });
            res.status(500).send(`فشل إرسال الرسالة الخاصة: ${error.message}. تأكد من تفعيل Guild Members Intent لبوتك.`);
        }
    });
});

// =========================================================================
// توجيهات لملفات HTML (المسارات)
// =========================================================================

// توجيه لصفحة تسجيل الدخول
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// توجيه لصفحة إنشاء حساب
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// المسار الرئيسي: يتحقق من تسجيل الدخول ويقوم بالتوجيه
app.get('/', (req, res) => {
    if (req.session.userId) {
        // إذا كان المستخدم مسجل الدخول، اذهب إلى لوحة التحكم الرئيسية (index.html)
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    } else {
        // إذا لم يكن مسجل الدخول، اذهب إلى صفحة تسجيل الدخول
        res.redirect('/login');
    }
});

// حماية صفحات التحكم: تتطلب المصادقة
app.get('/voice-control.html', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'voice-control.html'));
});
app.get('/discord-broadcast.html', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'discord-broadcast.html'));
});
app.get('/manage-bots.html', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'manage-bots.html'));
});


app.listen(port, () => {
    console.log(`الخادم يعمل على http://localhost:${port}`);
    console.log('يرجى زيارة http://localhost:3000 لبدء الاستخدام.');
});