const Router = ({ base = '', routes = [] } = {}) => ({
    __proto__: new Proxy({}, {
        get: (target, prop, receiver) => (route, ...handlers) =>
            routes.push([
                prop.toUpperCase(),
                RegExp(`^${(base + route)
                    .replace(/(\/?)\*/g, '($1.*)?')
                    .replace(/\/$/, '')
                    .replace(/:(\w+)(\?)?(\.)?/g, '$2(?<$1>[^/]+)$2$3')
                    .replace(/\.(?=[\w(])/, '\\.')
                    }/*$`),
                handlers,
            ]) && receiver
    }),
    routes,
    async handle(request, ...args) {
        let response, match,
            url = new URL(request.url)
        request.query = Object.fromEntries(url.searchParams)
        for (let [method, route, handlers] of routes) {
            if ((method === request.method || method === 'ALL') && (match = url.pathname.match(route))) {
                request.params = match.groups
                for (let handler of handlers) {
                    if ((response = await handler(request.proxy || request, ...args)) !== undefined) return response
                }
            }
        }
    }
})

const router = Router();

const static = {
    style: `<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Roboto", "Oxygen", "Ubuntu", "Cantarell", "Fira Sans", "Droid Sans", "Helvetica Neue", sans-serif; background-color: #17191a; }
#box { margin-top: 80px; margin-left: 10%; }
h1 { font-weight: normal; font-size: 48px; line-height: 150%; color: #a1a1a1; }
p { position: absolute; font-size: 24px; line-height: 150%; color: #f1f1f1; }
input { background: none; border: 1px solid #fff; border-radius: 0px; padding: 5px; color: #fff; width: 200px; }
button { background: none; color: #fff; padding: 3px 10px; border: 1px solid #fff; cursor: pointer; }
button:hover { opacity: 80%; }
</style>`,
    e400: (status, name) =>  new Response(`<!DOCTYPE html>
<head>
    <meta charSet="utf-8" />
    <title>${status} ${name}</title>
    <link rel="icon" href="https://cdn.arcsky.net/v1.ico" />
${static.style}
</head>
<body>
    <div id="box">
        <h1>${status} ${name}</h1>
        <p>ArcSky/${Version}</p>
    </div>
</body>
</html>`, { status: status, headers: { "Content-Type": "text/html" }})
}

const defaults = {
    e400: () => static.e400(400, "Bad Request"),
    e401: () => static.e400(401, "Unauthorized"),
    e402: () => static.e400(402, "Payment Required"),
    e403: () => static.e400(403, "Forbidden"),
    e404: () => static.e400(404, "Not Found"),
    apiError: (msg, status) => new Response(JSON.stringify({error: true, message:msg}), {status, headers: { "Content-Type": "application/json" }})
}



router.get("/", async (request) => {
    let session = await checkSession(request);
    if (session) {
        const { hostname } = new URL(request.url);
        return Response.redirect(`https://${hostname}/user/${session.username}`)        
    } else {
        return new Response(await KV.get("app:html:index"), {  headers: { "Content-Type": "text/html" } })
    }
})


router.get("/user/:id", async request => {
    let [session, owner] = await Promise.all([checkSession(request), KV.get("users:"+request.params.id, {type:"json"})]);
    if (!owner) return new Response("404 - User not found", { status: 404, headers: { "Content-Type": "text/html" } })
    
    let isOwner = session.username == owner.username;
    
    // Hide profile if owner's visibility is set to private, or is not the owner 
    if (owner.visibility > 0 || isOwner) {
        try {
            let [html, dives] = await Promise.all([KV.get("app:html:profile"), KV.get("users:"+owner.username+"dives", {type: 'json'})])
            if (!dives) dives = [];
            
            let displayed = {
                favorite: [],
                most_recent: [],
            };
            if (owner.favorite_dives) {
                owner.favorite_dives.forEach(index => {
                    if (dives[index]) {
                        displayed.favorite.push(dives[index]);
                    };
                });
            };
            
            dives.slice(-10).forEach(dive => {
                if (dive.hidden || !isOwner) return;
                displayed.most_recent.push(dive);
            });
    
            // Find the max depth from all the dives
            let maxDepth = 0;
            let maxTime = 0;
            let avgDepth = 0;
            let avgTime = 0;
            let avgTemp = 0;


            // Calculate the average bewtween a min a max
            function avg(min, max) {
                return (min + max) / 2;
            }

            // Find the average air usage from all the dives            
            let avgAirUsage = 0;

            // Number of dives
            let diveCount = 0;
            dives.forEach(dive => {
                diveCount++;
                // Find the max time from all the dives
                if (dive.depth > maxDepth) maxDepth = dive.depth;

                // Find the max time from all the dives
                if (dive.time > maxTime) maxTime = dive.time;

                // Find the average depth of all the dives
                avgDepth += dive.depth.avg;

                // Find the average time of all the dives
                avgTime += dive.time;

                // Find the average temperature of all the dives
                avgTemp += dive.temperature.avg;

                // Find the average air usage of all the dives
                avgAirUsage += dive.o2.start - dive.o2.end;
            });
            avgDepth = avgDepth / diveCount;
            avgTime = avgTime / diveCount;
            avgTemp = avgTemp / diveCount;
            avgAirUsage = avgAirUsage / diveCount;

            // Find the five most common locations for all the dives
            let locations = {};
            dives.forEach(dive => {
                if (dive.location) {
                    if (!locations[dive.location]) locations[dive.location] = 0;
                    locations[dive.location]++;
                }
            });
            let topLocations = Object.keys(locations).sort((a, b) => locations[b] - locations[a]).slice(0, 5);


            const account = {
                username: owner.username,
                name: owner.display_name,
                pfp: owner.pfp,
                visibility: owner.visibility,
                metric: owner.metric,
                bio: owner.bio,
                self: isOwner,
                stats: {
                    diveCount,
                    favorite_dives: displayed.favorite.length,
                    maxDepth,
                    maxTime,
                    avgDepth,
                    avgTime,
                    avgTemp,
                    avgAirUsage,
                    topLocations
                }
            };
            const data = {
                account,
                displayed,
                depthUnit: account.metric ? 'm' : 'ft',
                tempUnit: account.metric ? 'C' : 'F',
                pressureUnit: account.metric ? 'bar' : 'psi',
            };
            return new Response(html
                .replaceAll("__NAME__", account.name)
                .replace("__BIO__", account.bio)
                .replaceAll("__PFP__", account.pfp)
                .replaceAll("__USERNAME__", account.username)
                .replaceAll("__NUM_DIVES__", diveCount)
                .replace("__DATA__", JSON.stringify(data)), { headers: { "Content-Type": "text/html" } });
        } catch (err) {
            await logError(err, request);
            return new Response("500 - Internal Server Error", { status: 500, headers: { "Content-Type": "text/html" } })
        }
    } else {
        return new Response("This user has a private profile")
    }    
})

// Account object example
const EXAMPLE_account = {
    username: "",
    pfp: "",
    visibility: 0,
    metric: false,
    favorite_dives: [],
    num_dives: 0,
    bio: "",
};   

// Dive log object example
const EXAMPLE_diveLog = {
    time: {
        start: "",
        end: "",
        duration: 0,
    },
    depth: {
        max: 0,
        avg: 0
    },
    o2: {
        start: "",
        end: "",
        mixture: "",
    },
    location: "",
    notes: "",
    temperature: {
        min: 0,
        max: 0,
        avg: 0
    },
    weight: "",
    deco: {
        depth: "",
        time: ""
    },
    dive_type: ["Wreck", "Reef", "Cave", "Search & Recovery", "Deep Dive", "Night Dive", "Altitude Dive", "Ice Dive"],
    equipment: "",
    buddies: [],
    environment: {
        sky: ["Sunny", "Cloudy", "Dark", "Raining", "Snowing", "Storming", "Foggy", "Overcast", "Clear", "Stormy", "Foggy", "Overcast", "Clear"],
        water: ["Clear", "Salty", "Fresh", "Salty", "Fresh"],
        visibility: 0
    },
    photos: [],
    videos: [],
    tags: [],
    rating: 0,
    clothes: ""
}



// Dive Page
router.get("/user/:user_id/:dive_index", async  request => {
    // Make sute the dive_index is a number
    if (!isNaN(request.params.dive_index) && isFinite(request.params.dive_index)) return new Response("Invalid dive number")
    
    const [session, owner] = await Promise.all([checkSession(request), KV.get("users:"+request.params.user_id, {type: 'json'})]);
    if (!owner) {
        return new Response("User not found", {status: 404, headers: { "Content-Type": "text/html" }});
    };

    // Check visibility settings, and don't return the page if the user does not allow it to be public.
    let canAccess = false;
    if (session.username === owner.username) canAccess = true;
    else if (owner.visibility > 1) canAccess = true;
    // If its public or the owner/author is accessing it then allow it.
    if (canAccess) {
        const [dives, html] = await Promise.all([KV.get("users:"+session.username+":dives", { type:"json" }), KV.get("app:html:dive")]);
        // Make sure the dive exists
        const dive = dives[request.params.dive_index];
        if (dive) {
            return new Response(html.replace("__DATA__", JSON.stringify({dive})), { headers: { "Content-Type": "text/html" } })
        } else {
            return new Response("404 - Dive Not Found", { status: 404, headers: { "Content-Type": "text/html" } })
        }
    } else {
        return new Response("403 - This user has a private profile", { status: 403, headers: { "Content-Type": "text/html" } })
    }
})






// Location for login and signup
// THIS LOCATION IS RATE LIMITED by my lord and savior, Cloudflare :)
router.post("/api/auth", async (request) => {
    // Check if the request body is valid JSON
    let body;
    try {
        body = await request.json()
    } catch (err) {
        return defaults.apiError(err, 400)
    }
    // Check if the request body contains the correct keys
    if (!body) return defaults.apiError("No body", 400);
    // Make sure the type of request is valid
    if (!["login", "register"].includes(body.type)) return defaults.apiError("Invalid type", 400);
    
    // Never trust the client
    if (!body.username || !body.password) return defaults.apiError("Missing username or password", 400);
    if (!/^[a-zA-Z0-9_]+$/.test(body.username)) return defaults.apiError("Invalid username", 400);
    // Make sure no one try something fishy to get a longer name
    if (body.username.length < 3) return defaults.apiError("Username must be at least 3 characters", 400);
    if (body.username.length > 20) return defaults.apiError("Username too long", 400);
    if (body.password.length < 6) return defaults.apiError("Password must be at least 6 characters", 400);
    if (body.password.length > 256) return defaults.apiError("Password must be less than 256 characters", 400);


    // Make sure the username is not a reserved word
    if (["ADMIN", "DASHBOARD", "STAFF", "EMPLOYEE", "USER", "PRIVACY", "TERMS", "TOS", "SETTINGS", "SETTING", "AUTH", "API", "APIS", "DOCS", "DIVE", "INFO", "INFORMATION", "ABOUT", "PFP", "ACCOUNT"].includes(body.username.toUpperCase())) return defaults.apiError("Invalid Username", 400);

    if (body.type === "login") {
        // Get the user from the KV store
        let user = await KV.get("users:"+body.username, {type: 'json'});
        if (user) {
            // Hash the password and make sure its correct
            const password = await hashPassword(body.password);
            if (password === user.password) {
                // Don't allow a login if the account has been disabled
                if (user.disabled) return defaults.apiError("This account has been disabled", 403);


                // Create a random token for the session key
                const token = await newToken();

                // Store the session in KV with a 7 day expiry
                await KV.put(`sessions:${token}`, JSON.stringify({
                    accept: true,
                    username: user.username,
                    display_name: user.display_name,
                    userAgent: request.headers.get('user-agent'),
                    ip: request.headers.get('CF-Connecting-IP')
                }), { expirationTtl: 604800, metadata: { username: user.username, created: +Date.now(), expires: +Date.now() + 604800000 } });
                // Make a response with the token and set the clients cookie to the token
                let res = new Response("OK", {status: 200})

                // If used in production, set the cookie domain to same domain as app
                const { hostname } = new URL(request.url);
                res.headers.set('Set-Cookie', `session=${token}; Domain=${hostname}; Path=/; Secure; HttpOnly; Max-Age=604800`)
                return res;
            } else return defaults.apiError("Invalid Password", 403)
        } else {
            return defaults.apiError("Invalid Account", 403)
        }
    } else if (body.type === "register") {
        // To prevent spam captcha the register, we don't want to allow a user to register if they are not human.
        if (!body.captcha) return defaults.apiError("No captcha", 400);
        try {
            let verify = await fetch("https://hcaptcha.com/siteverify", {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: `secret=${CAPTCHA_SECRET}&response=${body.captcha}`
            });
            verify = await verify.json();
            if (verify.success) {
                // If captcha is valid
                // Make sure the username is not taken
                let user = await KV.get("users:"+body.username, { type: 'json' });
                if (user) {
                    return defaults.apiError("Username already taken", 403)
                } else {
                    user = {
                        username: body.username,
                        password: await hashPassword(body.password),
                        display_name: body.username,
                        pfp: null,
                        metric: true,
                        visibility: 0,
                        favorite_dives: [],
                        bio: "",
                        disabled: false
                    };
                    // Save the new username and return a 200 response, so the client can login with the new account.
                    await KV.put("users:"+body.username, JSON.stringify(user), {metadata: { username: user.username, created: +Date.now(), last_login: null }});
                    return new Response("OK", {status: 200});
                }
            } else {
                return defaults.apiError("Invalid Captcha", 403)
            }
        } catch (err) {
            // Catch an errors that happen, log them, and return an error to the client.
            await logError(err, request);
            return defaults.apiError("THERE WAS AN ERROR", 500)
        }
    } else {
        return defaults.apiError("Invalid type", 400)
    }
});


// Location for updating the user's settings
router.patch("/api/account", async request => {
    let session = await checkSession(request);
    if (session) {
        let account = await KV.get('users:'+session.username, { type:"json" })
        if (!account) return defaults.apiError("401 Unauthorized", 401)
        if (account.disabled) return defaults.apiError("403 This account has been disabled", 403)
        
        const type = request.headers.get("update-type");
        if (type === "pfp") {
            account.pfp = "";//
            session.pfp = "";//
            try {
                const session_id = getSessionToken(request);
                await Promise.all([
                    KV.put('users:'+session.username, JSON.stringify(account)),
                    KV.put(`sessions:${session_id}`, JSON.stringify(session))
                ]);
                return new Response(contentHash)
            } catch (err) {
                return defaults.apiError("Error trying to save updates to account", 500);
            }
        } else if (type === "settings") {
            const settings = await request.json();
            if (settings.metric) account.metric = true;
            else account.metric = false;
            if (settings.visibility) account.visibility = settings.visibility;
            else account.visibility = 0;
            try {
                const session_id = getSessionToken(request);
                await Promise.all([
                    KV.put('users:'+session.username, JSON.stringify(account)),
                    KV.put(`sessions:${session_id}`, JSON.stringify(session))
                ]);
                return new Response(contentHash)
            } catch (err) {
                return defaults.apiError("Error trying to save updates to account", 500);
            }
        } else {
            return defaults.apiError("Invalid 'update-type' in Header", 400);
        }
    } else {
        return defaults.apiError("401 Unauthorized", 401)
    }
})


router.post("/api/dive", async request => {
    let session = await checkSession(request);
    if (!session) return defaults.apiError("401 Unauthorized", 401);

    let body = await request.json()
    if (!body) return defaults.e400();
    
    let account = await KV.get('users:'+session.username, { type:'json' });
    if (!account) return defaults.apiError("401 Unauthorized", 401);

    let dives = await KV.get('users:'+session.username+":dives", { type:"json" });
    dives = dives || [];
    
    // Make sure dive is not already in the dives array by array index value
    if (dives.findIndex(dive => dive.id === body.id) !== -1) return defaults.apiError("Dive already exists", 400);
    
    // Push the dive to the to the dives array in the index if the dive id
    let dive = {
        id: body.id,
        body
    }
    dives.push(dive);
    if (dives.length > 15000) return defaults.apiError("Too many dives, Sorry", 400);

    // sort dives by number id descending
    dives.sort((a, b) => { return b.id - a.id; });

    // Save the dives array to the KV store
    try {
        await KV.put('users:'+session.username+":dives", JSON.stringify(dives), { metadata: { updated: +Date.now() } });
        return new Response("OK", {status: 200});
    } catch (err) {
        return defaults.apiError("Error trying to save dives to account", 500);
    }
})




router.get("/logout", async request => {
    const session_id = getSessionToken(request);
    if (session_id) {
        await KV.delete(`sessions:${session_id}`);
    };
    let res = new Response(null, {status: 302});
    res.headers.set('Set-Cookie', `session=null;Domain=.arcsky.net; Secure; HttpOnly; Max-Age=0`);
    res.headers.set('location', "https://arcsky.net/")
    if (sid) {
        await KV.delete('session:'+sid);
        return res;
    } else return res;
})



router.get("/favicon.ico", () => {
    return Response.redirect("https://cdn.arcsky.net/v1.ico", 301)
})

router.all("*", () => defaults.e404())

addEventListener("fetch", (event) => {
    event.respondWith(router.handle(event.request))
});

async function logError(err, request) {
    await KV.put(`app:logging:error:${+Date.now()}`, JSON.stringify({message: err.message, stack: err.stack, created: +Date.now(), userAgent: request.headers.get('user-agent')}));
}


async function shaHash (value) {
    const text = new TextEncoder().encode(value);
    const hashBuffer = await crypto.subtle.digest( { name: "SHA-256" }, text);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

async function HashMd(buffer) {
    const hashBuffer = await crypto.subtle.digest( { name: "md5" }, buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}


async function hashPassword(value) {
    return await shaHash("$" + value + "" + Fluff)
}

function getSessionToken(request) {
    const cookie = request.headers.get("cookie");
    let session = cookie && cookie.includes('session=');
    if (session) {
        const cookies = new URLSearchParams(cookie);
        session = cookies.get('session');
        if (session && session.length === (String(Fluff).length)*2) {
            return session
        } else return false
    } else return false
}

async function checkSession(request) {
    const session_id = getSessionToken(request);
    if (session_id) {
        const session = await KV.get(`sessions:${session_id}`, { type:"json" });
        if (session && session.accept) {
            return session
        } else return false
    } else return false
}


async function newToken() {
    let token = await crypto.getRandomValues(new TextEncoder().encode(Fluff));
    token = Array.from(new Uint8Array(token));
    token = token.map(b => b.toString(16).padStart(2, '0')).join('');
    return token
}