import http from '@/axios/index.js';

export function loginUserInfo() {
    return http.get('/my/loginUserInfo')
}

export function resetPassword(password, currentPassword) {
    return http.put('/my/resetPassword', {password, currentPassword})
}

export function userDelete() {
    return http.delete('/my/delete')
}

