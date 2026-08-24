using ISCM.Application.Interfaces;
using ISCM.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;

namespace ISCM.Application.Validators;

public class CatalogValidator : ICatalogValidator
{
    private readonly IEnumerable<IHardeningCheck> _checks;

    public CatalogValidator(IEnumerable<IHardeningCheck> checks)
    {
        _checks = checks;
    }

    public void Validate()
    {
        var errors = new List<string>();
        var controls = ControlCatalog.GetAll().ToList();

        // 1. بررسی تعداد کنترل‌های Baseline (باید دقیقاً 17 باشد)
        var baselineCount = controls.Count(c => c.IsBaseline);
        if (baselineCount != 17)
        {
            errors.Add($"[CRITICAL] Baseline control count is {baselineCount}, expected 17.");
        }

        // 2. بررسی تکراری نبودن ControlIdها
        var duplicateControlIds = controls
            .GroupBy(c => c.ControlId)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToList();

        if (duplicateControlIds.Any())
        {
            errors.Add($"[CRITICAL] Duplicate ControlIds found: {string.Join(", ", duplicateControlIds)}");
        }

        // 3. بررسی تکراری نبودن TechnicalCheckIdها در کل کاتالوگ
        var allTechIds = controls.SelectMany(c => c.TechnicalCheckIds).ToList();
        var duplicateTechIds = allTechIds
            .GroupBy(id => id)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToList();

        if (duplicateTechIds.Any())
        {
            errors.Add($"[CRITICAL] Duplicate TechnicalCheckIds found: {string.Join(", ", duplicateTechIds)}");
        }

        // 4. بررسی چک‌های یتیم (Orphan): چک‌هایی که در DI ثبت شده‌اند اما در کاتالوگ نیستند
        var registeredCheckIds = _checks.Select(c => c.CheckId).ToHashSet();
        var mappedCheckIds = allTechIds.ToHashSet();

        var orphans = registeredCheckIds.Except(mappedCheckIds).ToList();
        if (orphans.Any())
        {
            errors.Add($"[WARNING] Orphan checks (Registered in DI but not in Catalog): {string.Join(", ", orphans)}");
        }

        // 5. بررسی معکوس: IDهایی که در کاتالوگ هستند اما چکشان در DI ثبت نشده
        var unmapped = mappedCheckIds.Except(registeredCheckIds).ToList();
        if (unmapped.Any())
        {
            errors.Add($"[WARNING] Catalog IDs not found in DI registration: {string.Join(", ", unmapped)}");
        }

        // اگر خطایی وجود داشت، برنامه با خطا متوقف شود
        if (errors.Any())
        {
            var msg = "=== CATALOG INTEGRITY VALIDATION FAILED ===\n" + string.Join("\n", errors);
            throw new InvalidOperationException(msg);
        }
    }
}