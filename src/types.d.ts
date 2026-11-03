// Los .sh se empaquetan como texto (ver scripts/build.mjs).
declare module "*.sh" {
  const contenido: string;
  export default contenido;
}
