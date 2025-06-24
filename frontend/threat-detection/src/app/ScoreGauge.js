'use client';
import { CircularProgressbar, buildStyles } from 'react-circular-progressbar';
import 'react-circular-progressbar/dist/styles.css';

export default function ScoreGauge({ value }) {
  const percentage = Math.round(value * 100);

  const getColor = () => {
    if (value > 0.8) return '#00FF00'; // verde
    if (value > 0.5) return '#FFBF00'; // amarelo
    if (value > 0.3) return '#FF8000'; // laranja
    return '#FF0000'; // vermelho
  };

  const getInterpretation = () => {
    if (value > 0.8) return 'Risco baixo';
    if (value > 0.5) return 'Risco moderado';
    if (value > 0.3) return 'Risco alto';
    return 'Risco crítico';
  };

  return (
    <div className="flex flex-col items-center justify-center gap-4">
      <div className="w-40 h-40">
        <CircularProgressbar
          value={percentage}
          text={`${percentage}/100`}
          strokeWidth={10}
          styles={buildStyles({
            textColor: 'white',
            pathColor: getColor(),
            trailColor: '#333',
            textSize: '20px',
          })}
        />
      </div>
      <p className="text-white text-xl font-semibold">{getInterpretation()}</p>
    </div>
  );
}
