import React, { useState, useEffect } from 'react'
import { SubscriptionPlan } from '@/model/types/payment'
import { Button } from '@/view/components/ui/Button'
import { Card } from '@/view/components/ui/Card'
import { Badge } from '@/view/components/ui/Badge'
import { CheckIcon } from 'lucide-react'

interface SubscriptionPlansProps {
  plans: SubscriptionPlan[]
  currentPlanId?: string
  onSelectPlan: (plan: SubscriptionPlan) => void
  isLoading?: boolean
}

export const SubscriptionPlans: React.FC<SubscriptionPlansProps> = ({
  plans,
  currentPlanId,
  onSelectPlan,
  isLoading = false,
}) => {
  const [selectedPlan, setSelectedPlan] = useState<SubscriptionPlan | null>(null)

  const formatPrice = (cents: number, interval: string) => {
    const price = new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
    }).format(cents / 100)
    return `${price}/${interval}`
  }

  const isCurrentPlan = (planId: string) => planId === currentPlanId
  const isPopular = (plan: SubscriptionPlan) => plan.name.toLowerCase().includes('pro')

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
      {plans.map(plan => (
        <Card
          key={plan.id}
          className={`relative p-6 ${
            selectedPlan?.id === plan.id
              ? 'ring-2 ring-blue-500 border-blue-500'
              : 'border-gray-200'
          } ${isCurrentPlan(plan.id) ? 'bg-blue-50' : 'bg-white'}`}
        >
          {isPopular(plan) && (
            <Badge
              variant="primary"
              className="absolute -top-2 left-1/2 transform -translate-x-1/2"
            >
              Most Popular
            </Badge>
          )}

          <div className="text-center mb-6">
            <h3 className="text-xl font-bold text-gray-900 mb-2">{plan.name}</h3>
            <p className="text-gray-600 mb-4">{plan.description}</p>
            <div className="text-3xl font-bold text-blue-600">
              {formatPrice(plan.priceCents, plan.interval)}
            </div>
          </div>

          <ul className="space-y-3 mb-6">
            {plan.features.map((feature, index) => (
              <li key={index} className="flex items-center">
                <CheckIcon className="h-5 w-5 text-green-500 mr-3 flex-shrink-0" />
                <span className="text-gray-700">{feature}</span>
              </li>
            ))}
          </ul>

          <Button
            onClick={() => {
              setSelectedPlan(plan)
              onSelectPlan(plan)
            }}
            disabled={isLoading || isCurrentPlan(plan.id)}
            className="w-full"
            variant={isCurrentPlan(plan.id) ? 'secondary' : 'default'}
          >
            {isCurrentPlan(plan.id) ? 'Current Plan' : isLoading ? 'Processing...' : 'Select Plan'}
          </Button>
        </Card>
      ))}
    </div>
  )
}
