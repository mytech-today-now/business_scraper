import React from 'react'
import { render, screen } from '@testing-library/react'
import { LineChart, BarChart, PieChart, ChartDataPoint } from '../Charts'

describe('Charts Components', () => {
  const mockData: ChartDataPoint[] = [
    { name: 'Item 1', value: 100, color: '#3b82f6' },
    { name: 'Item 2', value: 200, color: '#ef4444' },
    { name: 'Item 3', value: 150, color: '#10b981' },
  ]

  describe('LineChart', () => {
    it('should render line chart with data', () => {
      render(<LineChart data={mockData} width={400} height={200} />)
      
      const svg = screen.getByRole('img', { hidden: true })
      expect(svg).toBeInTheDocument()
      expect(svg).toHaveAttribute('width', '400')
      expect(svg).toHaveAttribute('height', '200')
    })

    it('should render "No data available" when data is empty', () => {
      render(<LineChart data={[]} />)
      
      expect(screen.getByText('No data available')).toBeInTheDocument()
    })

    it('should render with custom stroke color and width', () => {
      render(
        <LineChart 
          data={mockData} 
          strokeColor="#ff0000" 
          strokeWidth={4}
        />
      )
      
      const svg = screen.getByRole('img', { hidden: true })
      expect(svg).toBeInTheDocument()
    })

    it('should render dots when showDots is true', () => {
      render(<LineChart data={mockData} showDots={true} />)
      
      const svg = screen.getByRole('img', { hidden: true })
      expect(svg).toBeInTheDocument()
    })

    it('should handle single data point', () => {
      const singleData = [{ name: 'Single', value: 100 }]
      render(<LineChart data={singleData} />)
      
      const svg = screen.getByRole('img', { hidden: true })
      expect(svg).toBeInTheDocument()
    })

    it('should apply custom className', () => {
      const { container } = render(
        <LineChart data={mockData} className="custom-chart" />
      )
      
      expect(container.firstChild).toHaveClass('custom-chart')
    })
  })

  describe('BarChart', () => {
    it('should render bar chart with data', () => {
      render(<BarChart data={mockData} width={400} height={200} />)
      
      const svg = screen.getByRole('img', { hidden: true })
      expect(svg).toBeInTheDocument()
      expect(svg).toHaveAttribute('width', '400')
      expect(svg).toHaveAttribute('height', '200')
    })

    it('should render "No data available" when data is empty', () => {
      render(<BarChart data={[]} />)
      
      expect(screen.getByText('No data available')).toBeInTheDocument()
    })

    it('should show values when showValues is true', () => {
      render(<BarChart data={mockData} showValues={true} />)
      
      const svg = screen.getByRole('img', { hidden: true })
      expect(svg).toBeInTheDocument()
    })

    it('should use custom bar color', () => {
      render(<BarChart data={mockData} barColor="#ff0000" />)
      
      const svg = screen.getByRole('img', { hidden: true })
      expect(svg).toBeInTheDocument()
    })

    it('should truncate long names', () => {
      const longNameData = [
        { name: 'Very Long Item Name That Should Be Truncated', value: 100 }
      ]
      render(<BarChart data={longNameData} />)
      
      const svg = screen.getByRole('img', { hidden: true })
      expect(svg).toBeInTheDocument()
    })

    it('should handle zero values', () => {
      const zeroData = [
        { name: 'Zero', value: 0 },
        { name: 'Positive', value: 100 }
      ]
      render(<BarChart data={zeroData} />)
      
      const svg = screen.getByRole('img', { hidden: true })
      expect(svg).toBeInTheDocument()
    })
  })

  describe('PieChart', () => {
    it('should render pie chart with data', () => {
      render(<PieChart data={mockData} width={200} height={200} />)
      
      const svg = screen.getByRole('img', { hidden: true })
      expect(svg).toBeInTheDocument()
      expect(svg).toHaveAttribute('width', '200')
      expect(svg).toHaveAttribute('height', '200')
    })

    it('should render "No data available" when data is empty', () => {
      render(<PieChart data={[]} />)
      
      expect(screen.getByText('No data available')).toBeInTheDocument()
    })

    it('should show labels when showLabels is true', () => {
      render(<PieChart data={mockData} showLabels={true} />)
      
      expect(screen.getByText('Item 1')).toBeInTheDocument()
      expect(screen.getByText('Item 2')).toBeInTheDocument()
      expect(screen.getByText('Item 3')).toBeInTheDocument()
    })

    it('should show percentages when showPercentages is true', () => {
      render(<PieChart data={mockData} showLabels={true} showPercentages={true} />)
      
      // Total is 450, so percentages should be calculated
      expect(screen.getByText(/22.2%/)).toBeInTheDocument() // 100/450
      expect(screen.getByText(/44.4%/)).toBeInTheDocument() // 200/450
      expect(screen.getByText(/33.3%/)).toBeInTheDocument() // 150/450
    })

    it('should not show labels when showLabels is false', () => {
      render(<PieChart data={mockData} showLabels={false} />)
      
      expect(screen.queryByText('Item 1')).not.toBeInTheDocument()
      expect(screen.queryByText('Item 2')).not.toBeInTheDocument()
      expect(screen.queryByText('Item 3')).not.toBeInTheDocument()
    })

    it('should handle single slice', () => {
      const singleData = [{ name: 'Single', value: 100 }]
      render(<PieChart data={singleData} showLabels={true} showPercentages={true} />)
      
      expect(screen.getByText('Single (100.0%)')).toBeInTheDocument()
    })

    it('should use default colors when not provided', () => {
      const dataWithoutColors = [
        { name: 'Item 1', value: 100 },
        { name: 'Item 2', value: 200 },
      ]
      render(<PieChart data={dataWithoutColors} />)
      
      const svg = screen.getByRole('img', { hidden: true })
      expect(svg).toBeInTheDocument()
    })
  })

  describe('Chart Data Validation', () => {
    it('should handle null data gracefully', () => {
      render(<LineChart data={null as any} />)
      expect(screen.getByText('No data available')).toBeInTheDocument()
    })

    it('should handle undefined data gracefully', () => {
      render(<BarChart data={undefined as any} />)
      expect(screen.getByText('No data available')).toBeInTheDocument()
    })

    it('should handle negative values in bar chart', () => {
      const negativeData = [
        { name: 'Negative', value: -50 },
        { name: 'Positive', value: 100 }
      ]
      render(<BarChart data={negativeData} />)
      
      const svg = screen.getByRole('img', { hidden: true })
      expect(svg).toBeInTheDocument()
    })

    it('should handle very large numbers', () => {
      const largeData = [
        { name: 'Large', value: 1000000 },
        { name: 'Larger', value: 2000000 }
      ]
      render(<LineChart data={largeData} />)
      
      const svg = screen.getByRole('img', { hidden: true })
      expect(svg).toBeInTheDocument()
    })
  })

  describe('Accessibility', () => {
    it('should provide tooltips for data points in line chart', () => {
      render(<LineChart data={mockData} showDots={true} />)
      
      const svg = screen.getByRole('img', { hidden: true })
      expect(svg).toBeInTheDocument()
    })

    it('should provide tooltips for bars in bar chart', () => {
      render(<BarChart data={mockData} />)
      
      const svg = screen.getByRole('img', { hidden: true })
      expect(svg).toBeInTheDocument()
    })

    it('should provide tooltips for pie slices', () => {
      render(<PieChart data={mockData} />)
      
      const svg = screen.getByRole('img', { hidden: true })
      expect(svg).toBeInTheDocument()
    })
  })

  describe('Responsive Behavior', () => {
    it('should use default dimensions when not specified', () => {
      render(<LineChart data={mockData} />)
      
      const svg = screen.getByRole('img', { hidden: true })
      expect(svg).toHaveAttribute('width', '400')
      expect(svg).toHaveAttribute('height', '200')
    })

    it('should handle very small dimensions', () => {
      render(<BarChart data={mockData} width={50} height={50} />)
      
      const svg = screen.getByRole('img', { hidden: true })
      expect(svg).toHaveAttribute('width', '50')
      expect(svg).toHaveAttribute('height', '50')
    })

    it('should handle very large dimensions', () => {
      render(<PieChart data={mockData} width={1000} height={1000} />)
      
      const svg = screen.getByRole('img', { hidden: true })
      expect(svg).toHaveAttribute('width', '1000')
      expect(svg).toHaveAttribute('height', '1000')
    })
  })
})
