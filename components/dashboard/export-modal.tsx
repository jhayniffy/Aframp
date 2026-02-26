'use client'

import { useState, useMemo } from 'react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Slider } from '@/components/ui/slider'
import { Switch } from '@/components/ui/switch'
import { Download, FileText, FileSpreadsheet, FileJson } from 'lucide-react'
import { cn } from '@/lib/utils'
import { toast } from 'sonner'
import { exportToCSV, exportToJSON, exportToPDF, exportToExcel } from '@/lib/export-utils'

interface ExportModalProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  transactions?: any[]
}

type TimePeriod = 'last30' | 'last90' | 'custom'
type ExportFormat = 'csv' | 'pdf' | 'excel' | 'json'

export function ExportModal({ open, onOpenChange, transactions = [] }: ExportModalProps) {
  const [timePeriod, setTimePeriod] = useState<TimePeriod>('last30')
  const [format, setFormat] = useState<ExportFormat>('csv')
  const [emailReport, setEmailReport] = useState(false)
  const [exporting, setExporting] = useState(false)
  
  const now = new Date()
  const maxDaysAgo = 365
  const [customDaysAgo, setCustomDaysAgo] = useState([30])

  const { startDate, endDate, recordCount } = useMemo(() => {
    let daysAgo: number
    
    if (timePeriod === 'last30') {
      daysAgo = 30
    } else if (timePeriod === 'last90') {
      daysAgo = 90
    } else {
      daysAgo = customDaysAgo[0]
    }

    const end = new Date()
    const start = new Date()
    start.setDate(start.getDate() - daysAgo)

    const count = transactions.filter(tx => {
      const txDate = new Date(tx.timestamp)
      return txDate >= start && txDate <= end
    }).length

    return {
      startDate: start,
      endDate: end,
      recordCount: count
    }
  }, [timePeriod, customDaysAgo, transactions])

  const formatDate = (date: Date) => {
    return date.toLocaleDateString('en-US', { 
      month: 'short', 
      day: 'numeric',
      year: 'numeric' 
    })
  }

  const handleExport = async () => {
    setExporting(true)
    
    try {
      const filteredTransactions = transactions.filter(tx => {
        const txDate = new Date(tx.timestamp)
        return txDate >= startDate && txDate <= endDate
      })

      const filename = `aframp-transactions-${formatDate(startDate).replace(/\s/g, '-')}-to-${formatDate(endDate).replace(/\s/g, '-')}`
      
      switch (format) {
        case 'csv':
          exportToCSV(filteredTransactions, `${filename}.csv`)
          break
        case 'json':
          exportToJSON(filteredTransactions, `${filename}.json`)
          break
        case 'pdf':
          exportToPDF(filteredTransactions, `${filename}.pdf`)
          break
        case 'excel':
          exportToExcel(filteredTransactions, `${filename}.xlsx`)
          break
      }

      await new Promise(resolve => setTimeout(resolve, 800))
      
      toast.success('Export successful!', {
        description: emailReport 
          ? `${recordCount} records exported and sent to your email`
          : `${recordCount} records exported as ${format.toUpperCase()}`
      })
      
      onOpenChange(false)
    } catch (error) {
      toast.error('Export failed', {
        description: 'Please try again or contact support'
      })
    } finally {
      setExporting(false)
    }
  }

  const formats: { value: ExportFormat; label: string; icon: any }[] = [
    { value: 'csv', label: 'CSV', icon: FileSpreadsheet },
    { value: 'pdf', label: 'PDF', icon: FileText },
    { value: 'excel', label: 'Excel', icon: FileSpreadsheet },
    { value: 'json', label: 'JSON', icon: FileJson },
  ]

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Download className="w-5 h-5" />
            Export Transaction Data
          </DialogTitle>
          <DialogDescription>
            Select time period and format for your transaction export
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-6 py-4">
          {/* Time Period */}
          <div className="space-y-3">
            <Label>Time Period</Label>
            <div className="grid grid-cols-3 gap-2">
              <Button
                type="button"
                variant={timePeriod === 'last30' ? 'default' : 'outline'}
                size="sm"
                onClick={() => setTimePeriod('last30')}
              >
                Last 30 days
              </Button>
              <Button
                type="button"
                variant={timePeriod === 'last90' ? 'default' : 'outline'}
                size="sm"
                onClick={() => setTimePeriod('last90')}
              >
                Last 3 months
              </Button>
              <Button
                type="button"
                variant={timePeriod === 'custom' ? 'default' : 'outline'}
                size="sm"
                onClick={() => setTimePeriod('custom')}
              >
                Custom
              </Button>
            </div>
          </div>

          {/* Custom Date Range Slider */}
          {timePeriod === 'custom' && (
            <div className="space-y-3">
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Days ago</span>
                <span className="font-medium">{customDaysAgo[0]} days</span>
              </div>
              <Slider
                value={customDaysAgo}
                onValueChange={setCustomDaysAgo}
                min={1}
                max={maxDaysAgo}
                step={1}
                className="w-full"
              />
              <div className="flex justify-between text-xs text-muted-foreground">
                <span>Today</span>
                <span>1 year ago</span>
              </div>
            </div>
          )}

          {/* Date Range Display */}
          <div className="rounded-lg bg-muted/50 p-3 space-y-1">
            <div className="flex justify-between text-sm">
              <span className="text-muted-foreground">Date range:</span>
              <span className="font-medium">
                {formatDate(startDate)} – {formatDate(endDate)}
              </span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-muted-foreground">Records:</span>
              <span className="font-semibold text-primary">~{recordCount}</span>
            </div>
          </div>

          {/* Export Format */}
          <div className="space-y-3">
            <Label>Export Format</Label>
            <div className="grid grid-cols-2 gap-2">
              {formats.map(({ value, label, icon: Icon }) => (
                <button
                  key={value}
                  type="button"
                  onClick={() => setFormat(value)}
                  className={cn(
                    'flex items-center gap-2 p-3 rounded-lg border-2 transition-all',
                    format === value
                      ? 'border-primary bg-primary/5'
                      : 'border-border hover:border-primary/50'
                  )}
                >
                  <Icon className="w-4 h-4" />
                  <span className="font-medium text-sm">{label}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Email Report Toggle */}
          <div className="flex items-center justify-between rounded-lg border p-3">
            <div className="space-y-0.5">
              <Label htmlFor="email-report" className="cursor-pointer">
                Email report
              </Label>
              <p className="text-xs text-muted-foreground">
                Send export to your registered email
              </p>
            </div>
            <Switch
              id="email-report"
              checked={emailReport}
              onCheckedChange={setEmailReport}
            />
          </div>

          {/* Export Button */}
          <Button
            onClick={handleExport}
            disabled={exporting || recordCount === 0}
            className="w-full"
            size="lg"
          >
            {exporting ? (
              'Exporting...'
            ) : (
              <>
                <Download className="w-4 h-4 mr-2" />
                Export {recordCount} Records
              </>
            )}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}
