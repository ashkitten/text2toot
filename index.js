const bodyParser = require("body-parser");
const crypto = require("crypto");
const ece = require("http_ece");
const express = require("express");
const fs = require("fs");
const getRawBody = require("raw-body");
const http = require("http");
const lockfile = require("proper-lockfile");
const path = require("path");
const request = require("request");
const requestPromise = require("request-promise-native");
const stripTags = require("striptags");
const twilio = require("twilio");
const urlBase64 = require("urlsafe-base64");
const urlUtil = require("url");

const config = require("./config");

function reload(module) {
    delete require.cache[require.resolve(module)];
    return require(module);
}

async function writeJson(file, obj) {
    const release = await lockfile.lock(file);
    fs.writeFileSync(file, JSON.stringify(obj), "utf8");
    await release();
}

function range(...args) {
    start = args.length > 1 ? args[0] : 0;
    end   = args.length > 1 ? args[1] : args[0];
    step  = args.length > 2 ? args[2] : 1;
    return Array.from({ length: Math.ceil((end - start) / step) }, (v, k) => k * step + start);
}

function ReductionProxy(name, target) {
    return new Proxy(target, {
        get: (obj, prop) => {
            const matches = Array.from(Object.keys(obj).filter(key => key.startsWith(prop)));
            if (matches.length > 1) throw `${prop} is ambiguous as a ${name}`;
            if (matches.length < 1) throw `${prop} is not a valid ${name}`;
            return obj[matches[0]];
        },
    });
}

const visibilities = ReductionProxy("visibility", {
    direct: "direct",
    private: "private",
    unlisted: "unlisted",
    public: "public",
});

const notifySubcommands = ReductionProxy("subcommand", {
    subscribe: "subscribe",
    unsubscribe: "unsubscribe",
});

const commands = new ReductionProxy("command", {
    [null]: async (params) => {
        const { NumMedia: numMedia, From: userId } = params;
        if (!numMedia) throw "must attach media or provide a command";
        const user = reload("./users")[userId];
        if (!user) throw "must register first";
        const { instance, token, mediaIds = [] } = user;

        Array.prototype.push.apply(mediaIds, await Promise.all(range(numMedia).map(async i => {
            const attachment = await requestPromise({
                url: `https://${instance}/api/v1/media`,
                method: "POST",
                formData: {
                    file: {
                        value: request(params[`MediaUrl${i}`]),
                        options: {
                            filename: path.basename(urlUtil.parse(params[`MediaUrl${i}`]).pathname),
                            contentType: params[`MediaContentType${i}`],
                        },
                    },
                },
                headers: { "Authorization": `Bearer ${token}` },
                json: true,
            });
            if (attachment.error) throw attachment.error;
            else return attachment.id;
        })));

        const users = Object.assign(reload("./users"), {
            [userId]: Object.assign(user, { mediaIds }),
        });
        await writeJson("./users.json", users);

        return "media uploaded";
    },

    clear_media: async (params) => {
        const { From: userId } = params;
        const users = Object.assign(reload("./users"), {
            [userId]: Object.assign(user, { mediaIds: [] }),
        });
        await writeJson("./users.json", users);
    },

    post: async (params) => {
        const { Body: input, From: userId } = params;
        const user = reload("./users")[userId];
        if (!user) throw "must register first";
        const { instance, token, mediaIds } = user;

        let [, vis = "public", cw, text] = input.match(/\w+(?:\.(\w+))?(?:\[\[(.*?)\]\])?\s+([\s\S]*)/);

        const status = await requestPromise({
            url: `https://${instance}/api/v1/statuses`,
            method: "POST",
            body: { status: text, spoiler_text: cw, visibility: visibilities[vis], media_ids: mediaIds },
            headers: { "Authorization": `Bearer ${token}` },
            json: true,
        });
        if (status.error) throw status.error;

        const users = Object.assign(reload("./users"), {
            [userId]: Object.assign(user, { mediaIds: [] }),
        });
        await writeJson("./users.json", users);

        return status.url;
    },

    register: async (params) => {
        const { Body: message, From: userId } = params;
        const [, instance, token] = message.split(/\s/);

        const users = Object.assign(reload("./users"), {
            [userId]: { instance, token },
        });
        await writeJson("./users.json", users);

        return "registration success";
    },

    notify: async (params) => {
        const { Body: message, From: userId } = params;
        const user = reload("./users")[userId];
        if (!user) throw "must register first";
        const { instance, token } = user;

        const subcommand = notifySubcommands[message.split(/\s/)[1]];

        if (subcommand === "subscribe") {
            const curve = crypto.createECDH("prime256v1");
            curve.setPrivateKey(config.pushKey, "base64");

            await requestPromise({
                url: `https://${instance}/api/v1/push/subscription`,
                method: "POST",
                body: {
                    subscription: {
                        endpoint: `${config.baseUrl}/push`,
                        keys: {
                            p256dh: curve.getPublicKey("base64"),
                            auth: config.pushAuth,
                        },
                    },
                    data: {
                        alerts: {
                            mention: true,
                        },
                    },
                },
                headers: { "Authorization": `Bearer ${token}` },
                json: true,
            });

            return "successfully subscribed to mention notifications";
        }

        if (subcommand === "unsubscribe") {
            const { From: userId } = params;
            const { instance, token } = reload("./users")[userId];

            await requestPromise({
                url: `https://${instance}/api/v1/push/subscription`,
                method: "DELETE",
                headers: { "Authorization": `Bearer ${token}` },
                json: true,
            });

            return "successfully unsubscribed from mention notifications";
        }
    },
});

if (!fs.existsSync("./users.json")) {
    fs.writeFileSync("./users.json", "{}", "utf8");
}

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));

app.post("/sms", async (req, res) => {
    const { body: params } = req;
    const { Body: message } = params;

    const twiml = new twilio.twiml.MessagingResponse();
    try {
        //if (!twilio.validateRequest(
        //    config.authToken,
        //    req.get("X-Twilio-Signature") || "",
        //    `${config.baseUrl}${req.originalUrl}`,
        //    params,
        //)) throw "bad request";

        twiml.message(await commands[message.match(/\w+/)](params));
    } catch (e) {
        console.log(e);
        twiml.message(`error: ${e.toString()}`);
    }

    res.writeHead(200, { "Content-Type": "text/xml" });
    res.end(twiml.toString());
});

app.post("/push", async (req, res) => {
    const curve = crypto.createECDH("prime256v1");
    curve.setPrivateKey(config.pushKey, "base64");
    const serverKey = req.get("Crypto-Key").match(/dh=(.+?)(?:;|$)/)[1];
    const rawBody = await getRawBody(req, { length: req.get("Content-Length") });
    const decrypted = ece.decrypt(rawBody, {
        version: req.get("Content-Encoding"),
        authSecret: config.pushAuth,
        privateKey: curve,
        dh: serverKey,
        salt: req.get("Encryption").match(/salt=(.+?)(?:;|$)/)[1],
    });
    const pushPayload = JSON.parse(decrypted);

    const users = reload("./users");
    const userId = Object.keys(users).filter(key => users[key].token === pushPayload.access_token);
    const { instance, token } = users[userId];

    const notification = await requestPromise({
        url: `https://${instance}/api/v1/notifications/${pushPayload.notification_id}`,
        method: "GET",
        headers: { "Authorization": `Bearer ${token}` },
        json: true,
    });

    const cw = notification.status.spoiler_text ? `cw: ${notification.status.spoiler_text}\n` : "";
    const content = stripTags(notification.status.content.replace("<br>", "\n"))

    twilio(config.accountSid, config.authToken).messages.create({
        body: `${pushPayload.title}:\n${cw}${content}`,
        from: config.outgoingNumber,
        to: userId,
        mediaUrl: notification.status.media_attachments.map(attachment => attachment.url),
    }).done();

    res.end();
});

http.createServer(app).listen(config.port, () => {
    console.log(`listening for webhook requests on port ${config.port}`);
});
