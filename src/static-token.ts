import { Application, NextFunction } from "express";
import {
  IPluginAuth,
  IStorageManager,
  IPluginMiddleware,
  IBasicAuth,
  Config as VerdaccioConfig,
  Security,
  Callback,
  RemoteUser,
  JWTSignOptions,
  AllowAccess,
  AuthAccessCallback,
  PackageAccess,
} from "@verdaccio/types";
import merge from "lodash/merge";

const pluginName = "static-token";

interface PluginConfig {
  token: string;
  user: string;
  password: string;
}

interface Config extends VerdaccioConfig {
  name: string;
  middlewares: { [pluginName]: PluginConfig[] };
  auth: { [pluginName]: PluginConfig[] };
}

interface Auth extends IBasicAuth<Config> {
  config: Config;
  apiJWTmiddleware(): NextFunction;
  jwtEncrypt(user: RemoteUser, signOptions: JWTSignOptions): Promise<string>;
  webUIJWTmiddleware(): NextFunction;
}

const TIME_EXPIRATION_7D = "7d" as const;

const defaultSecurity: Security = {
  api: {
    legacy: false,
    jwt: {
      sign: {
        expiresIn: TIME_EXPIRATION_7D,
      },
      verify: {},
    },
  },
  web: {
    sign: {
      expiresIn: TIME_EXPIRATION_7D,
    },
    verify: {},
  },
};

function getSecurity(config: VerdaccioConfig) {
  return merge({}, defaultSecurity, config.security);
}

export class StaticToken
  implements IPluginMiddleware<Config>, IPluginAuth<Config>
{
  config: Config;
  security: Security;

  constructor(config: Config) {
    this.config = config;
    this.security = getSecurity(this.config);
  }

  authenticate(user: string, _password: string, cb: Callback) {
    const found = this.config.auth[pluginName].some((e) => e.user === user);
    if (found) {
      console.log(`Allowing access to: ${user}`);
      cb(null, [user]);
      return;
    }

    // do nothing: go to next auth plugin configured
    cb(null, null);
  }

  allow_access(
    _user: RemoteUser,
    _pkg: AllowAccess & PackageAccess,
    cb: AuthAccessCallback
  ) {
    cb(null, true);
  }

  register_middlewares(
    app: Application,
    auth: Auth,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    storage: IStorageManager<Config>
  ) {
    // RFC6750 says Bearer must be case sensitive
    const datas = this.config.middlewares[pluginName];
    const security = getSecurity(this.config);

    app.use(async function (req: Request, _res: Response, next: Callback) {
      const authorization = req.headers["authorization"];
      if (authorization && authorization !== "") {
        const found = datas.find((e) => e.token === authorization.substr(7));
        console.log(found);
        if (found) {
          console.log("Applying custom token");
          const payload: RemoteUser = {
            name: found.user,
            real_groups: [],
            groups: [],
          };
          const sign = security?.api?.jwt?.sign || {
            expiresIn: TIME_EXPIRATION_7D,
          };
          const ret = await auth.jwtEncrypt(payload, sign);
          req.headers["authorization"] = `Bearer ${ret}`;
          console.log(req.headers["authorization"]);
        }
      }
      next();
    });
  }
}
