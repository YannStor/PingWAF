import type {
  CreateVisitorRequest,
  UpdateVisitorRequest,
  Visitor,
} from '@/api/types'

export const VISITOR_REMARK_MAX_LENGTH = 500

export interface VisitorFormState {
  email: string
  password: string
  name: string
  remark: string
  disabled: boolean
  siteIds: string[]
}

export const EMPTY_VISITOR_FORM: VisitorFormState = {
  email: '',
  password: '',
  name: '',
  remark: '',
  disabled: false,
  siteIds: [],
}

export function visitorFormFrom(visitor: Visitor): VisitorFormState {
  return {
    email: visitor.email,
    password: '',
    name: visitor.name,
    remark: visitor.remark,
    disabled: visitor.disabled,
    siteIds: visitor.site_ids,
  }
}

export function createVisitorPayload(
  form: VisitorFormState,
): CreateVisitorRequest {
  return {
    email: form.email.trim(),
    password: form.password,
    name: form.name.trim(),
    remark: form.remark.trim(),
    disabled: form.disabled,
    site_ids: form.siteIds,
  }
}

export function updateVisitorPayload(
  form: VisitorFormState,
): UpdateVisitorRequest {
  return {
    name: form.name.trim(),
    remark: form.remark.trim(),
    disabled: form.disabled,
    site_ids: form.siteIds,
    ...(form.password === '' ? {} : { password: form.password }),
  }
}
