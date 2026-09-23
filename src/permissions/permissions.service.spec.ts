import { ALL_PERMISSIONS, PermissionsService } from './permissions.service';

describe('Օրվա ամփոփման և առաջադրանքների վերլուծության միասնական իրավունք', () => {
  it('ունի միայն մեկ ai_task_analysis անուն՝ առանց ավտոմատ և ձեռքով տարբերակների', () => {
    expect(ALL_PERMISSIONS.filter(p => p === 'ai_task_analysis')).toEqual(['ai_task_analysis']);
    expect(ALL_PERMISSIONS).not.toContain('ai_daily_review');
    expect(ALL_PERMISSIONS).not.toContain('ai_task_analysis_auto');
  });
  it('ավելացնում է կատալոգի իրավունքը, բայց չի նշանակում որևէ դերի կամ աշխատակցի', async () => {
    const upsert = jest.fn().mockResolvedValue({});
    const service = new PermissionsService({ permission: { upsert } } as any);
    await service.seedPermissions();
    expect(upsert).toHaveBeenCalledWith({ where: { name: 'ai_task_analysis' }, create: { name: 'ai_task_analysis' }, update: {} });
    expect(upsert).toHaveBeenCalledTimes(ALL_PERMISSIONS.length);
  });
});
