'use client';
import GaugeChart from 'react-gauge-chart';

export default function ScoreGauge({ value }) {
  const getInterpretation = (score) => {
    if (score < 0.3) return 'Risco baixo';
    if (score < 0.5) return 'Risco moderado';
    if (score < 0.7) return 'Risco moderado';
    return 'Risco crítico';
  };

  return (
    <div className="w-full flex flex-col items-center">
      <GaugeChart
        id="score-gauge"
        nrOfLevels={20}
        arcWidth={0.3}
        percent={value}
        textColor="#000"
        colors={['#00FF00', '#FFBF00', '#FF0000']}
        formatTextValue={() => `${Math.round(value * 100)}%`}
      />
      <p className="mt-2 text-3xl font-bold">
        {getInterpretation(value)}
      </p>
    </div>
  );
}