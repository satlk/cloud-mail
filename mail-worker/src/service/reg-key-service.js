import orm from '../entity/orm';
import regKey from '../entity/reg-key';
import { inArray, like, eq, desc, sql, or } from 'drizzle-orm';
import roleService from './role-service';
import BizError from '../error/biz-error';
import { formatDetailDate, toUtc } from '../utils/date-uitil';
import userService from './user-service';
import { t } from '../i18n/i18n.js';

const regKeyService = {

	async add(c, params, userId) {

		let {code,roleId,count,expireTime} = params;

        if (typeof code !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/.test(code)
            || !Number.isInteger(count) || count < 1 || count > 1000
            || !Number.isInteger(roleId) || roleId <= 0
            || typeof expireTime !== 'string' || !Number.isFinite(Date.parse(expireTime))
            || toUtc(expireTime).tz('Asia/Shanghai').startOf('day').isBefore(toUtc().tz('Asia/Shanghai').startOf('day'))) {
            throw new BizError('注册码参数无效', 400);
        }

		const regKeyRow = await orm(c).select().from(regKey).where(eq(regKey.code, code)).get();

		if (regKeyRow) {
			throw new BizError(t('isExistRegKye'));
		}

		const roleRow = await roleService.selectById(c, roleId);
		if (!roleRow) {
			throw new BizError(t('roleNotExist'));
		}

		expireTime = formatDetailDate(expireTime)

		await orm(c).insert(regKey).values({code,roleId,count,userId,expireTime}).run();
	},

	async delete(c, params) {
		let {regKeyIds} = params;
		regKeyIds = regKeyIds.split(',').map(id => Number(id));
		await orm(c).delete(regKey).where(inArray(regKey.regKeyId,regKeyIds)).run();
	},

	async clearNotUse(c) {
		let now = formatDetailDate(toUtc().tz('Asia/Shanghai').startOf('day'))
		await orm(c).delete(regKey).where(or(eq(regKey.count, 0),sql`datetime(${regKey.expireTime}, '+8 hours') < datetime(${now})`)).run();
	},

	selectByCode(c, code) {
		return orm(c).select().from(regKey).where(eq(regKey.code, code)).get();
	},

	async list(c, params) {

		const {code} = params
		let query = orm(c).select().from(regKey)

		if (code) {
			query = query.where(like(regKey.code, `${code}%`))
		}

		const regKeyList = await query.orderBy(desc(regKey.regKeyId)).all();
		const roleList = await roleService.roleSelectUse(c);

		const today = toUtc().tz('Asia/Shanghai').startOf('day')

		regKeyList.forEach(regKeyRow => {

			const index = roleList.findIndex(roleRow => roleRow.roleId === regKeyRow.roleId)
			regKeyRow.roleName = index > -1 ? roleList[index].name : ''

			const expireTime = toUtc(regKeyRow.expireTime).tz('Asia/Shanghai').startOf('day');

			if (expireTime.isBefore(today)) {
				regKeyRow.expireTime = null
			}
		})

		return regKeyList;
	},

    async consume(c, id, roleId) {
        // ponytail: reserve before provisioning; failed account creation consumes a use, admin can reissue.
        const row = await c.env.db.prepare(
            "UPDATE reg_key SET count = count - 1 WHERE rege_key_id = ? AND role_id = ? AND count > 0 AND date(expire_time, '+8 hours') >= date('now', '+8 hours') RETURNING rege_key_id"
        ).bind(id, roleId).first();
        if (!row) throw new BizError('注册码无效、已用完或已过期', 400);
    },

	async history(c, params) {
		const { regKeyId } = params;
		return userService.listByRegKeyId(c, regKeyId);
	}
}

export default regKeyService;
