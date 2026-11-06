// Runs src/ under Node: resolves extensionless imports and replaces the native module.
import { registerHooks } from 'node:module';

registerHooks({
  resolve(specifier, context, next) {
    if (specifier === 'expo') return next(new URL('./expo.ts', import.meta.url).href, context);
    if (specifier.startsWith('.') && !context.parentURL?.includes('/node_modules/') && !/\.[cm]?[jt]s$/.test(specifier)) {
      return next(`${specifier}.ts`, context);
    }
    return next(specifier, context);
  },
});
