// 本地预览：静态服务 public/，http://localhost:8787
const server = Bun.serve({
  port: 8787,
  async fetch(req) {
    let path = new URL(req.url).pathname;
    if (path.endsWith("/")) path += "index.html";
    const file = Bun.file("public" + path);
    return (await file.exists()) ? new Response(file) : new Response("Not found", { status: 404 });
  },
});
console.log(`http://localhost:${server.port}`);
