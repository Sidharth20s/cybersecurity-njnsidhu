package com.silentsentinel

import android.content.Context
import android.os.Build
import android.telephony.CellIdentityGsm
import android.telephony.CellIdentityLte
import android.telephony.CellIdentityNr  // 5G NR
import android.telephony.TelephonyManager

/**
 * Scans nearby cell towers for coarse geolocation.
 * Cell tower polygons are well-mapped and can give
 * 50m-500m accuracy depending on density.
 */
object CellTowerScanner {

    data class CellTowerInfo(
        val mcc: Int,
        val mnc: Int,
        val tac: Int?,      // Tracking Area Code
        val ci: Long?,      // Cell Identity
        val technology: String  // GSM, LTE, NR
    )

    fun getVisibleTowers(context: Context): List<CellTowerInfo> {
        val tm = context.applicationContext
            .getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager ?: return emptyList()

        return try {
            val allCells = tm.allCellInfo ?: return emptyList()

            allCells.mapNotNull { cell ->
                when {
                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && cell.cellIdentity is CellIdentityLte -> {
                        val lte = cell.cellIdentity as CellIdentityLte
                        CellTowerInfo(
                            mcc = lte.mccString?.toIntOrNull() ?: 0,
                            mnc = lte.mncString?.toIntOrNull() ?: 0,
                            tac = lte.tac,
                            ci = lte.ci,
                            technology = "LTE"
                        )
                    }
                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && cell.cellIdentity is CellIdentityGsm -> {
                        val gsm = cell.cellIdentity as CellIdentityGsm
                        CellTowerInfo(
                            mcc = gsm.mccString?.toIntOrNull() ?: 0,
                            mnc = gsm.mncString?.toIntOrNull() ?: 0,
                            tac = gsm.lac,
                            ci = gsm.cid?.toLong(),
                            technology = "GSM"
                        )
                    }
                    Build.VERSION.SDK_INT >= 29 && cell.cellIdentity is CellIdentityNr -> {
                        val nr = cell.cellIdentity as CellIdentityNr
                        CellTowerInfo(
                            mcc = nr.mccString?.toIntOrNull() ?: 0,
                            mnc = nr.mncString?.toIntOrNull() ?: 0,
                            tac = nr.tac,
                            ci = nr.nci,
                            technology = "NR"
                        )
                    }
                    else -> null
                }
            }
        } catch (e: SecurityException) {
            emptyList()
        }
    }
}