import { Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

interface ChartDatum { name: string; value?: number; count?: number; color?: string; fill?: string }

const tooltipStyle = { background: '#111827', border: '1px solid #263248', borderRadius: 6, color: '#dce5f2', fontSize: 11 }

export default function DashboardChart({ type, data }: { type: 'health' | 'severity'; data: ChartDatum[] }) {
  if (type === 'health') return <ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={data} dataKey="value" nameKey="name" innerRadius={52} outerRadius={75} paddingAngle={2} stroke="none">{data.map((entry) => <Cell key={entry.name} fill={entry.color} />)}</Pie><Tooltip contentStyle={tooltipStyle} /></PieChart></ResponsiveContainer>
  return <ResponsiveContainer width="100%" height="100%"><BarChart data={data} layout="vertical" margin={{ top: 8, right: 30, left: 12, bottom: 8 }}><XAxis type="number" hide /><YAxis type="category" dataKey="name" axisLine={false} tickLine={false} width={58} tick={{ fill: '#8a99ad', fontSize: 10 }} /><Tooltip cursor={{ fill: 'rgba(80,100,130,.08)' }} contentStyle={tooltipStyle} /><Bar dataKey="count" radius={[0, 3, 3, 0]} barSize={10}>{data.map((entry) => <Cell key={entry.name} fill={entry.fill} />)}</Bar></BarChart></ResponsiveContainer>
}
