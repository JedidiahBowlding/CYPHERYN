declare module "cloudflare:workers" {
  export const env: {
    DB?: import("@cloudflare/workers-types").D1Database;
  };
}
