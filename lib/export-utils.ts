interface Transaction {
  id: string
  type: string
  amount: string
  currency: string
  to?: string
  from?: string
  status: string
  timestamp: string
}

export function exportToCSV(transactions: Transaction[], filename: string) {
  const headers = ['ID', 'Type', 'Amount', 'Currency', 'To/From', 'Status', 'Timestamp']
  const rows = transactions.map(tx => [
    tx.id,
    tx.type,
    tx.amount,
    tx.currency,
    tx.to || tx.from || '-',
    tx.status,
    tx.timestamp
  ])

  const csvContent = [
    headers.join(','),
    ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
  ].join('\n')

  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
  const link = document.createElement('a')
  link.href = URL.createObjectURL(blob)
  link.download = filename
  link.click()
}

export function exportToJSON(transactions: Transaction[], filename: string) {
  const jsonContent = JSON.stringify(transactions, null, 2)
  const blob = new Blob([jsonContent], { type: 'application/json' })
  const link = document.createElement('a')
  link.href = URL.createObjectURL(blob)
  link.download = filename
  link.click()
}

export function exportToPDF(transactions: Transaction[], filename: string) {
  // Placeholder for PDF generation
  // In production, use jsPDF or similar library
  console.log('PDF export:', transactions, filename)
}

export function exportToExcel(transactions: Transaction[], filename: string) {
  // Placeholder for Excel generation
  // In production, use xlsx library
  console.log('Excel export:', transactions, filename)
}
