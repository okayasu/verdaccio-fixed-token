import { Config as VerdaccioConfig } from "@verdaccio/types";

export const pluginName = "fixed-token";

export interface PluginConfig {
  token: string;
  user: string;
  password: string;
  groups: string[];
}

export interface IConfig extends VerdaccioConfig {
  name: string;
  middlewares: { [pluginName]: PluginConfig[] };
  auth: { [pluginName]: PluginConfig[] };
}
