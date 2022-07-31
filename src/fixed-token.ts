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
import { IConfig, PluginConfig, pluginName } from "./config";

interface Auth extends IBasicAuth<IConfig> {
  config: IConfig;
  apiJWTmiddleware(): NextFunction;
  jwtEncrypt(user: RemoteUser, signOptions: JWTSignOptions): Promise<string>;
  webUIJWTmiddleware(): NextFunction;
}

const TIME_EXPIRATION_7D = "7d" as const;

function getSecurity(config: VerdaccioConfig): Security {
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
  return merge({}, defaultSecurity, config.security);
}

export class FixedToken
  implements IPluginMiddleware<IConfig>, IPluginAuth<IConfig>
{
  config: IConfig;
  allowUsers: PluginConfig[];

  constructor(config: IConfig) {
    this.config = config;
    this.allowUsers = config.auth[pluginName].concat(
      config.middlewares[pluginName]
    );
  }

  authenticate(user: string, _password: string, cb: Callback) {
    const found = this.allowUsers.some((e) => e.user === user);
    if (found) {
      // console.log(`Allowing access to: ${user}`);
      cb(null, [user]);
      return;
    }

    // do nothing: go to next auth plugin configured
    cb(null, null);
  }

  allow_access(
    user: RemoteUser,
    _pkg: AllowAccess & PackageAccess,
    cb: AuthAccessCallback
  ) {
    const found = this.allowUsers.find((e) => e.user === user.name);
    if (found) {
      // console.log("allow access");
      cb(null, true);
    } else {
      cb(null, false);
    }
  }

  register_middlewares(
    app: Application,
    auth: Auth,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    _storage: IStorageManager<IConfig>
  ) {
    // RFC6750 says Bearer must be case sensitive
    const datas = this.allowUsers;
    const security = getSecurity(this.config);

    app.use(async function (req: Request, _res: Response, next: Callback) {
      const authorization = req.headers["authorization"];
      if (authorization && authorization !== "") {
        const found = datas.find((e) => e.token === authorization.substr(7));
        // console.log(found);
        if (found) {
          // console.log("Applying custom token");
          const payload: RemoteUser = {
            name: found.user,
            real_groups: found.groups,
            groups: found.groups,
          };
          const sign = security?.api?.jwt?.sign || {
            expiresIn: TIME_EXPIRATION_7D,
          };
          const ret = await auth.jwtEncrypt(payload, sign);
          req.headers["authorization"] = `Bearer ${ret}`;
          // console.log(req.headers["authorization"]);
        }
      }
      next();
    });
  }
}
